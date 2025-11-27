from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests


def replay_requests(
    *,
    recordings_path: Path,
    base_url: str,
    auth_token: Optional[str],
    timeout: float,
    dry_run: bool = False,
) -> Dict[str, object]:
    recordings = _load_recordings(recordings_path)
    requests_list = recordings.get("requests", [])
    successes: List[Dict[str, object]] = []
    failures: List[Dict[str, object]] = []
    for idx, entry in enumerate(requests_list):
        method = (entry.get("method") or "GET").upper()
        path = entry.get("path") or "/"
        if not path.startswith("http://") and not path.startswith("https://"):
            path = path if path.startswith("/") else "/" + path
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        else:
            url = path
        headers = dict(entry.get("headers") or {})
        if auth_token and "authorization" not in {k.lower() for k in headers}:
            headers["Authorization"] = f"Bearer {auth_token}"
        body = entry.get("body")
        start = time.time()
        if dry_run:
            successes.append(
                {
                    "index": idx,
                    "method": method,
                    "path": path,
                    "status": "DRY_RUN",
                    "duration": 0.0,
                }
            )
            continue
        try:
            response = requests.request(
                method,
                url,
                json=body if isinstance(body, (dict, list)) else None,
                data=body if isinstance(body, (str, bytes)) else None,
                headers=headers,
                timeout=timeout,
            )
            duration = time.time() - start
            if 200 <= response.status_code < 400:
                successes.append(
                    {
                        "index": idx,
                        "method": method,
                        "path": path,
                        "status": response.status_code,
                        "duration": duration,
                    }
                )
            else:
                failures.append(
                    {
                        "index": idx,
                        "method": method,
                        "path": path,
                        "status": response.status_code,
                        "duration": duration,
                        "error": response.text[:256],
                    }
                )
        except Exception as exc:
            duration = time.time() - start
            failures.append(
                {
                    "index": idx,
                    "method": method,
                    "path": path,
                    "status": None,
                    "duration": duration,
                    "error": str(exc),
                }
            )

    summary = {
        "sent": len(requests_list) if not dry_run else 0,
        "success": len(successes),
        "failed": len(failures),
    }
    return {
        "summary": summary,
        "successes": successes,
        "failures": failures,
        "dryRun": dry_run,
    }


def _load_recordings(path: Path) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        data = {"requests": data}
    if "requests" not in data:
        raise ValueError("Recordings JSON must contain a 'requests' array.")
    return data



