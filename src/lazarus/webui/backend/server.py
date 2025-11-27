from __future__ import annotations

import threading
import time
import uuid
import asyncio
import json
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import os
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, HTMLResponse
from pydantic import BaseModel, Field

from lazarus.cli.main import run_pipeline


class JobRequest(BaseModel):
    binary: str
    ghidra: Optional[str] = None
    output: Optional[str] = Field(default="lazarus-output")
    generateBackend: bool = False
    generateMod: bool = False
    gameConfig: Optional[str] = None


class JobStatus(BaseModel):
    id: str
    status: str
    createdAt: float
    updatedAt: float
    result: Optional[Dict[str, str]] = None
    phase: Optional[str] = None
    schemaVersions: Optional[Dict[str, object]] = None


@dataclass
class Job:
    id: str
    request: JobRequest
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    logs: List[Dict[str, str]] = field(default_factory=list)
    result: Optional[Dict[str, str]] = None
    log_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    phase: str = "queued"
    events: List[Dict[str, str]] = field(default_factory=list)

    def log(self, level: str, message: str) -> None:
        with self.log_lock:
            entry = {
                "timestamp": time.time(),
                "level": level,
                "message": message,
            }
            self.logs.append(entry)
            if len(self.logs) > 500:
                self.logs = self.logs[-500:]
            self.updated_at = time.time()
            self.events.append({"timestamp": entry["timestamp"], "phase": self.phase, "status": self.status})

    def set_phase(self, phase: str) -> None:
        with self.log_lock:
            self.phase = phase
            self.events.append({"timestamp": time.time(), "phase": phase, "status": self.status})


app = FastAPI(
    title="Lazarus Web UI",
    description="Meta-tool job runner",
    version="0.1.0",
)

# Add CORS middleware for localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=2)
jobs: Dict[str, Job] = {}
lock = threading.Lock()
repo_root = Path(__file__).resolve().parents[4]
history_path = Path(os.environ.get("LAZARUS_JOB_HISTORY", repo_root / "lazarus_jobs_history.json"))
job_history: List[Dict[str, object]] = []


def load_history() -> None:
    if history_path.exists():
        try:
            data = json.loads(history_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                job_history.extend(data)
        except Exception:
            pass


def persist_history(entry: Dict[str, object]) -> None:
    job_history.append(entry)
    try:
        history_path.write_text(json.dumps(job_history, indent=2))
    except Exception:
        pass


load_history()


@app.get("/")
async def root():
    try:
        return {
            "message": "Lazarus Web UI backend",
            "github": "https://github.com/lukascollishawm",
            "jobs": len(jobs),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {e}")


@app.get("/ui")
async def frontend():
    try:
        frontend_path = Path(__file__).resolve().parent.parent / "frontend" / "index.html"
        if not frontend_path.exists():
            raise HTTPException(status_code=404, detail=f"Frontend not found at {frontend_path}")
        content = frontend_path.read_text(encoding="utf-8")
        # Return as plain HTML response with explicit headers
        from fastapi.responses import Response
        return Response(
            content=content,
            media_type="text/html; charset=utf-8",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error serving frontend: {e}")


@app.post("/jobs", response_model=JobStatus)
def create_job(payload: JobRequest):
    job_id = str(uuid.uuid4())
    job = Job(id=job_id, request=payload)
    with lock:
        jobs[job_id] = job
    executor.submit(run_job, job)
    return serialize_job(job)


@app.get("/jobs", response_model=List[JobStatus])
def list_jobs():
    with lock:
        return [serialize_job(job) for job in jobs.values()]


@app.get("/jobs/history")
def get_history():
    return job_history


@app.get("/jobs/{job_id}", response_model=JobStatus)
def get_job(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return serialize_job(job)


@app.get("/jobs/{job_id}/logs")
def get_job_logs(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    with job.log_lock:
        return list(job.logs)


@app.get("/jobs/{job_id}/logs/stream")
async def stream_job_logs(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        last_idx = 0
        while True:
            await asyncio.sleep(0.5)
            with job.log_lock:
                new_entries = job.logs[last_idx:]
                last_idx = len(job.logs)
                finished = job.status in {"completed", "failed"}
            if new_entries:
                for entry in new_entries:
                    yield f"data: {json.dumps(entry)}\n\n"
            if finished and not new_entries:
                break

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/jobs/{job_id}/events/stream")
async def stream_job_events(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        last_idx = 0
        while True:
            await asyncio.sleep(0.5)
            with job.log_lock:
                new_entries = job.events[last_idx:]
                last_idx = len(job.events)
                finished = job.status in {"completed", "failed"}
            for entry in new_entries:
                yield f"data: {json.dumps(entry)}\n\n"
            if finished and not new_entries:
                break

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/jobs/{job_id}/artifacts/{kind}")
def download_artifact(job_id: str, kind: str, background: BackgroundTasks):
    job = jobs.get(job_id)
    if not job or not job.result:
        raise HTTPException(status_code=404, detail="Job not found or no artifacts")

    path: Optional[Path] = None
    cleanup_file: Optional[Path] = None

    if kind == "raw":
        path = Path(job.result.get("rawJson", ""))
    elif kind == "report":
        path = Path(job.result.get("cleanReport", ""))
    elif kind == "payload":
        path = Path(job.result.get("payloadSchema", ""))
    elif kind == "backend":
        backend_dir = job.result.get("backendDir", "")
        if backend_dir:
            tmp_base = tempfile.mktemp()
            zip_path = Path(shutil.make_archive(tmp_base, "zip", root_dir=backend_dir))
            cleanup_file = zip_path
            path = zip_path
    elif kind == "mod":
        mod_dir = job.result.get("modDir", "")
        if mod_dir:
            tmp_base = tempfile.mktemp()
            zip_path = Path(shutil.make_archive(tmp_base, "zip", root_dir=mod_dir))
            cleanup_file = zip_path
            path = zip_path
    else:
        raise HTTPException(status_code=400, detail="Unknown artifact kind")

    if not path or not path.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")

    filename = path.name

    if cleanup_file:
        background.add_task(cleanup_file.unlink, missing_ok=True)

    return FileResponse(path, filename=filename, background=background if cleanup_file else None)


def run_job(job: Job) -> None:
    job.status = "running"
    job.phase = "analysis"
    job.log("info", "Job started")
    try:
        # Handle paths with spaces - Path() handles this automatically, but ensure they're expanded
        binary_path = Path(job.request.binary.strip()).expanduser().resolve()
        ghidra_path = Path(job.request.ghidra.strip()).expanduser().resolve() if job.request.ghidra and job.request.ghidra.strip() else None
        output_path = Path(job.request.output.strip() if job.request.output else "lazarus-output").expanduser().resolve()
        game_config_path = Path(job.request.gameConfig.strip()).expanduser().resolve() if job.request.gameConfig and job.request.gameConfig.strip() else None
        
        job.log("info", f"Binary: {binary_path}")
        if ghidra_path:
            job.log("info", f"Ghidra: {ghidra_path}")
        if game_config_path:
            job.log("info", f"Config: {game_config_path}")
        
        result = run_pipeline(
            binary=binary_path,
            ghidra=ghidra_path,
            output=output_path,
            generate_backend=job.request.generateBackend,
            generate_mod=job.request.generateMod,
            game_config=game_config_path,
            log_callback=lambda line: job.log("info", f"ghidra: {line}"),
        )
        if job.request.generateBackend:
            job.phase = "backend"
        elif job.request.generateMod:
            job.phase = "mod"
        else:
            job.phase = "completed"
        job.status = "completed"
        payload_fields = result["clean_data"].get("inferredPayloadFields", [])
        job.result = {
            "rawJson": str(result["raw_json"]),
            "cleanReport": str(result["clean_report"]),
            "backendDir": str(result["backend_dir"]) if result.get("backend_dir") else "",
            "modDir": str(result["mod_dir"]) if result.get("mod_dir") else "",
            "payloadSchema": str(result.get("payload_schema", "")),
            "payloadFields": payload_fields[:10],
            "functionLinks": result["clean_data"].get("functionPayloadLinks", [])[:10],
            "schemaVersions": result["clean_data"].get("payloadSchemaVersions", {}),
            "bundleDir": str(result.get("bundle_dir", "")),
        }
        job.log("info", "Job completed successfully")
        persist_history(
            {
                "id": job.id,
                "status": job.status,
                "phase": job.phase,
                "result": job.result,
                "createdAt": job.created_at,
                "updatedAt": job.updated_at,
            }
        )
    except Exception as exc:
        job.status = "failed"
        job.set_phase("failed")
        job.log("error", f"Job failed: {exc}")
    finally:
        job.updated_at = time.time()


def serialize_job(job: Job) -> JobStatus:
    return JobStatus(
        id=job.id,
        status=job.status,
        createdAt=job.created_at,
        updatedAt=job.updated_at,
        result=job.result,
        phase=job.phase,
        schemaVersions=(job.result or {}).get("schemaVersions"),
    )

