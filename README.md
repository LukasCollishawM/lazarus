# Lazarus

**Safety-first reverse-engineering framework for server emulation and RCE mitigation.**

Lazarus allows you to resurrect dead online modes for games by automating the analysis of game binaries and generating safe, schema-enforced server backends and client-side shims.

## Intentions

### 1. Server Revival
Resurrect multiplayer functionality for abandoned games by analyzing the client binary to understand its network protocol and generating a compatible replacement server. Lazarus helps you go from "dead binary" to "playable server" faster by automating protocol discovery.

### 2. RCE Mitigation via Network Shimming
Many older games have vulnerabilities in their network handling (e.g., buffer overflows, unsafe deserialization). Lazarus addresses this by generating a client-side shim (DLL) that acts as a middleware between the game and the network.
- **Interception**: The shim hooks network calls (using MinHook) to intercept traffic.
- **Sanitization**: It validates and sanitizes data before passing it to the game's legacy code, effectively patching Remote Code Execution (RCE) vulnerabilities without requiring source code access.
- **Safe Codegen**: The generated C++ code for the shim is designed with modern safety standards to prevent introducing new vulnerabilities.

### 3. Full Server Emulation via Code Generation
Lazarus automates the tedious parts of server emulation to ensure comprehensive coverage and safety:
- **Ghidra Automation**: Uses headless Ghidra scripts (`src/lazarus/ghidra_automation`) to identify network functions, packet structures, and encryption patterns in the game binary.
- **Deterministic Codegen**: Generates a strictly-typed backend (Fastify + Zod) and a matching C++ shim.
- **Canonical ABI**: Enforces a strict schema for all network communication. The generated backend (`src/lazarus/codegen/backend`) uses Zod for runtime validation, ensuring that the server rejects malformed or malicious packets before they are processed.

## How It Works

### Phase 1: Automated Analysis (Headless Ghidra)

Lazarus treats the game binary as the source of truth. Instead of manually clicking through a decompiler, it runs a suite of headless Ghidra scripts (`src/lazarus/ghidra_automation/scripts/`) to extract machine-readable facts:

1.  **Pattern Scanning**: `network_patterns_json.py` scans for RIP-relative loads and byte signatures to identify stable entry points for function hooking.
2.  **String Analysis**: It cross-references strings like "http", "api", "contracts" to find functions likely responsible for networking.
3.  **Heuristic Scoring**: Functions are scored based on their imports (e.g., `WinHttpSendRequest`, `recv`, `socket`) and internal structure (loops, array accesses) to identify high-probability targets for interception.
4.  **Data Extraction**: The scripts emit a JSON report (`analysis_report.json`) containing function addresses, signatures, and inferred packet structures.

### Phase 2: Schema Inference & The "Canonical ABI"

Using the raw analysis report, Lazarus constructs a **Canonical ABI** (Application Binary Interface) for the game's network layer. This ABI defines the strict contract that both the game client and the server must adhere to.

-   **Inferred Fields**: It guesses payload fields (e.g., `gameId`, `score`, `createdAt`) based on string references and memory access patterns within network functions.
-   **Strict Typing**: These fields are mapped to concrete types (e.g., `z.string().max(64)`, `z.number().int()`).
-   **Schema Sharing**: This schema is exported as both TypeScript (Zod schemas for the server) and C++ (structs for the client shim), ensuring the two sides never drift out of sync.

### Phase 3: Deterministic Code Generation

Lazarus uses the Canonical ABI to generate two complete software projects:

#### A. The Server Backend (`generated-backend/`)
A generic, safe-by-default **Node.js/Fastify** server.
-   **Zod Validation**: Every incoming request is validated against the generated schema *before* it reaches any logic. Malformed packets are rejected instantly.
-   **SQLite Persistence**: A lightweight database is set up with tables mirroring the inferred schema (`records`, `record_fields`).
-   **Routes**: API endpoints are created for discovered network functions (e.g., `/generated/upload_score`), ready for you to fill in the game logic.

#### B. The Client Shim (`generated-mod/`)
A **C++ DLL** designed to be injected into the game process.
-   **MinHook Integration**: It uses the patterns found in Phase 1 to hook the game's network functions at runtime.
-   **Payload Bridge**: A `GamePayloadContext` struct maps the game's raw memory to the sanitized Canonical ABI structs.
-   **Sanitization Layer**: When the game tries to send data, the shim intercepts it, validates it against the schema, serializes it to safe JSON, and sends it to your new backend, bypassing the game's potentially buggy legacy network stack.
-   **Instrumentation**: Includes a packet logger (`json_sink.cpp`) to dump traffic for further analysis or replay.

### Phase 4: Runtime Injection

An injector tool (`src/lazarus/injector/win32.py`) loads the generated DLL into the running game.
1.  **Privilege Escalation**: Acquires `SeDebugPrivilege` to access the game process.
2.  **Remote Load**: Allocates memory in the game process and forces a `LoadLibraryW` call to load the shim.
3.  **Hook Activation**: The shim's `DllMain` executes, installing hooks on the discovered network functions.

## Repository Structure

-   **`src/lazarus/ghidra_automation/`**: Runner and scripts for headless binary analysis.
-   **`src/lazarus/codegen/`**: Logic for generating the target server and mod code.
    -   `backend/`: Generates the TypeScript/Fastify server.
    -   `mod/`: Generates the C++ DLL for hooking and shimming.
-   **`src/lazarus/injector/`**: Tools for injecting the generated DLL (`win32.py`).
-   **`src/lazarus/webui/`**: Local Web UI for managing jobs and viewing logs.
-   **`src/lazarus/analysis/`**: Parsers for processing Ghidra output.

## Getting Started

1.  **Analyze**: Run the Ghidra automation to extract network patterns from your target game binary.
2.  **Generate**: Use the analysis report to generate a safe backend server and a client-side shim.
3.  **Inject**: Use the injector to load the shim into the game process.
4.  **Play**: The shim redirects traffic to your new, safe server.
