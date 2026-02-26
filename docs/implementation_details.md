# PANDORA - Implementation Details

PANDORA is a high-performance static analysis engine for HarmonyOS applications. It audits privacy compliance at the binary level by parsing Panda Assembly (`.pa`) files, the disassembled form of ArkTS/eTS bytecode. PANDORA can detect sensitive system API calls and collaborative collection patterns without requiring source code.

The core engine uses **fixed-point register-state tracking on CFGs** for in-function API detection, then extends the analysis with **global call graph construction + semantic-root backtracking (lifecycle entry tracing) + same-module lifecycle context annotation** to extract cross-function collaborative privacy subgraphs.

## Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [Architecture](#architecture)
- [Detection Paradigms](#detection-paradigms)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Rule System](#rule-system)
- [Output Format](#output-format)
- [How It Works](#how-it-works)
- [Performance](#performance)
- [Extensibility](#extensibility)
- [Limitations](#limitations)

---

## Overview

HarmonyOS applications are compiled into `.abc` (Ark Bytecode) files, which can be disassembled into `.pa` (Panda Assembly) text format using the `ark_disasm` tool. This analyzer parses `.pa` files and uses **register-tracking-based static analysis** to identify calls to privacy-sensitive system APIs (such as location, camera, contacts, device identifiers, etc.). It further applies **call graph analysis** to detect coordinated invocation patterns involving multiple privacy APIs.

Unlike simple string-matching approaches, this tool understands four distinct API invocation paradigms in HarmonyOS bytecode. It uses a register state machine to precisely track module references through instruction sequences, and builds a cross-function call graph to surface collaborative privacy data collection.

### Motivation

Privacy compliance auditing typically requires one of:
1. **Source code** — usually unavailable for third-party applications.
2. **Dynamic analysis** — requires device instrumentation and may miss infrequently executed code paths.
3. **Binary analysis** — can analyze any compiled application without source code.

This tool implements approach (3), providing automated, scalable binary-level privacy API detection and collaborative analysis.

---

## Core Features

- **Binary-level analysis** — Analyzes compiled `.pa` files directly; no source code required.
- **Four-paradigm detection** — Handles direct invocation, indirect (factory) chained invocation, callback invocation, and constant property access.
- **CFG fixed-point analysis** — Builds control-flow graphs with basic block splitting, try→handler edges, and register-state convergence.
- **String constant tracking** — Tracks `lda.str` values and chained property accesses (e.g., `sensor.SensorId.ACCELEROMETER`).
- **Global call graph** — Builds a cross-function call relationship graph to identify inter-function call chains.
- **Semantic-root backtracking** — Reverse BFS from sensitive APIs to HarmonyOS lifecycle entry points (such as `onCreate`, `onForeground`, `build`) or graph roots, locating the logical starting point of each behavior.
- **Lifecycle context annotation** — Collects all lifecycle methods in the same ViewPU module (such as `aboutToAppear`, `initialRender`, `onClick`) and attaches them as `lifecycle_context` metadata to each subgraph for downstream intent inference.
- **Deep call-chain extraction** — BFS from semantic roots to sensitive APIs, extracting complete call paths with function bodies.
- **Rule-driven detection** — 61 configurable YAML rules covering 11+ sensitive API categories.
- **False-positive filtering** — Automatically filters Promise chain methods (`.then`/`.catch`), logging calls, and resource cleanup operations.
- **Three output formats** — Simultaneously generates a JSON detection report, a subgraph JSON, and a Graphviz DOT visualization.
- **High performance** — Analysis of 1,248 functions and 16 subgraphs completes in approximately 0.4 seconds.

---

## Architecture

`main.py` is the CLI coordinator and drives the full pipeline. The architecture is organized into the following stages:

1. **Parser stage (`parser.py`)**: parses the `.pa` file into literals, records, and functions.
2. **Resolver stage (`resolver.py`)**: resolves module mappings through `Record -> LiteralArray -> Import Map` relationships.
3. **Detector stage (`detector.py`)**: performs instruction-level sensitive API detection via register-state tracking and rule matching.
4. **Graph analysis stage (`callgraph.py` + `subgraph.py`)**: constructs a global call graph and extracts collaborative privacy subgraphs.
5. **Rule layer (`rules/*.yaml`)**: supplies declarative detection rules consumed by the detector.
6. **Output layer**:
  - `output/results_*.json`: API detection report.
  - `output/subgraphs_*.json`: extracted privacy subgraphs (with function bodies and metadata).
  - `output/subgraphs_*.dot`: Graphviz visualization of subgraphs.

### Processing Flow

The end-to-end flow is:

1. Parse the `.pa` file into structured entities (`Literals`, `Records`, `Functions`).
2. Resolve imports from `Record -> LiteralArray -> Import Map`.
3. Run in-function register tracking and rule matching to generate `results_*.json`.
4. Build the global call graph across functions.
5. Mark sensitive graph nodes.
6. Backtrack to semantic roots with reverse BFS (typically lifecycle entry points) and collect same-module lifecycle context.
7. Extract privacy subgraphs using bidirectional BFS, attach function bodies, and annotate `lifecycle_context` metadata.
8. Emit `subgraphs_*.json` and `subgraphs_*.dot`.

---

## Detection Paradigms

This tool identifies four distinct privacy API invocation patterns in HarmonyOS bytecode.

### 1. Indirect Invocation (Factory Pattern)

A factory method first retrieves a service instance, and the actual data-access method is then called on that instance.

**Equivalent source code:**
```typescript
let pasteboard = pasteboard.getSystemPasteboard();  // factory method
let data = pasteboard.getData();                     // data access
```

**Bytecode instructions:**
```
ldexternalmodulevar 0x2
throw.undefinedifholewithname "pasteboard"
sta v5
lda v5
ldobjbyname 0x0, "getSystemPasteboard"    ◄─ factory method
callthis0 0x2, v5                          ◄─ returns instance
sta v6
lda v6
ldobjbyname 0x0, "getData"                ◄─ data access
callthis0 0x4, v6                          ◄─ actual call
```

**Detection mechanism:** The register tracker maintains `call_result` state along with the original module attribution, so the chained `.getData()` call is detected and annotated with context `"via getSystemPasteboard()"`.

### 2. Direct Invocation

A module method is called directly without an intermediate instance.

```
ldexternalmodulevar 0x3
ldobjbyname 0x0, "getCurrentLocation"     ◄─ property access
callthis1 0x2, v4, v5                     ◄─ direct call
```

### 3. Callback Invocation

A callback function is passed as an argument to an API method.

```
definefunc 0x6, ...                          ◄─ callback definition
sta v7                                       ◄─ v7 = closure
ldobjbyname 0x0, "on"
callthis3 0x8, v5, v6, v7, v8               ◄─ v7 is the closure argument
```

### 4. Constant Property Access

Read-only access to a module-level constant, with no method call.

```
ldexternalmodulevar 0x0
ldobjbyname 0x0, "productModel"            ◄─ property read
sta v4                                      ◄─ next non-call* instruction
```

---

## Project Structure

```
pa-privacy-analyzer/
├── main.py                          # CLI entry point: parse → detect → call graph → subgraph → output
│
├── pandora/                         # Core analysis layer
│   └── core/
│       ├── parser.py                # .pa file parsing (state machine: Literals → Records → Methods)
│       ├── resolver.py              # Module resolution (Record → LiteralArray → Import Map)
│       ├── cfg.py                   # Control-flow graph construction (basic blocks + exception edges + RPO)
│       ├── detector.py              # Register-tracking detection engine (four paradigms)
│       ├── callgraph.py             # Global call graph construction (inter-function call edge extraction)
│       └── subgraph.py              # Collaborative subgraph extraction (semantic-root backtracking + BFS)
│
├── rules/
│   └── privacy_api_rules.yaml       # 61+ privacy API detection rules
│
├── docs/
│   └── implementation_details.md    # This document
│
├── requirements.txt                 # Python dependencies (pyyaml)
│
└── output/                          # Auto-generated output directory
    ├── results_<name>_<ts>.json     # API detection results
    ├── subgraphs_<name>_<ts>.json   # Privacy subgraphs (JSON)
    └── subgraphs_<name>_<ts>.dot    # Privacy subgraphs (DOT visualization)
```

### Module Details

| Module | Description |
|------|------|
| `parser.py` | State-machine parser; extracts `ModuleLiteralArray`, `PaRecord`, and `PaFunction` |
| `resolver.py` | Builds a `{local_name: "@ohos:module"}` import map per function via longest-prefix matching from function → Record → LiteralArray |
| `cfg.py` | Lightweight CFG construction: basic block splitting, explicit/implicit edges, RPO computation |
| `detector.py` | Core detection engine: `RegisterTracker` (ACC + register state machine), `RuleMatcher` (indexed lookup), `ApiDetector` (instruction-level analysis) |
| `callgraph.py` | Global call graph: analyzes `definefunc`/`callthis*` instructions to build cross-function call edges; supports internal calls, external API calls, and callback calls |
| `subgraph.py` | Three-phase subgraph extraction: (1) sensitive node annotation, (2) semantic-root backtracking — reverse BFS to lifecycle entries or graph roots, plus same-module lifecycle context collection, (3) bidirectional BFS subgraph extraction with function body attachment and `lifecycle_context` metadata |
| `main.py` | CLI entry point: coordinates the full pipeline and generates three output files |

---

## Installation

### Prerequisites

- **Python 3.10+** (uses `match` syntax and type union `|`)
- **PyYAML** for parsing rule files

### Setup

```bash
cd pa-privacy-analyzer
pip install -r requirements.txt
```

### Obtaining `.pa` Files

```bash
ark_disasm input.abc output.pa
```

The `ark_disasm` tool is part of the [ArkCompiler Runtime Core](https://gitee.com/openharmony/arkcompiler_runtime_core) toolchain.

---

## Usage

### Basic Usage

```bash
# Default: JSON output to output/ directory (generates results + subgraphs + DOT)
python main.py path/to/modules.pa

# API-only mode (skip subgraph extraction for faster runs)
python main.py path/to/modules.pa --no-subgraph

# Print table format to console
python main.py path/to/modules.pa --format table

# Custom output directory
python main.py path/to/modules.pa -o custom_output/

# Verbose mode
python main.py path/to/modules.pa -v

# Custom rule file
python main.py path/to/modules.pa --rules custom_rules.yaml
```

### Output File Naming

JSON output is automatically saved to the `output/` directory with the following naming scheme:

```
output/results_<pa_file_stem>_<YYYYMMDD_HHMMSS>.json
output/subgraphs_<pa_file_stem>_<YYYYMMDD_HHMMSS>.json
output/subgraphs_<pa_file_stem>_<YYYYMMDD_HHMMSS>.dot
```

All three files share the same timestamp, ensuring they correspond to the same run.

### Command-Line Arguments

| Argument | Description | Default |
|------|------|------|
| `pa_file` | Path to the `.pa` file | (required) |
| `--format` | Output format: `json` or `table` | `json` |
| `-o, --output` | Output directory | `output/` |
| `--rules` | Custom YAML rule file | `rules/privacy_api_rules.yaml` |
| `--no-subgraph` | Skip call graph construction and subgraph extraction | `false` |
| `-v, --verbose` | Show verbose parsing details | `false` |

---

## Rule System

Rules are defined in `rules/privacy_api_rules.yaml` using a declarative YAML format.

### Rule Structure

```yaml
rules:
  - id: "CLIPBOARD_001"
    module: "@ohos:pasteboard"
    method: "getSystemPasteboard"
    paradigm: "indirect_invoke"
    category: "CLIPBOARD"
    description: "Get system pasteboard service instance"
```

### Supported Categories

| Category | Rule Count | Typical APIs |
|------|--------|----------|
| `DEVICE_INFO` | 12 | `deviceInfo.deviceType`, `.serial`, `.productModel` |
| `ACCOUNT_INFO` | 8 | `osAccount.getAccountManager`, `appAccount.getAllAccounts` |
| `NETWORK_INFO` | 8 | `wifiManager.getLinkedInfo`, `net.connection.getDefaultNet` |
| `PRECISE_LOCATION` | 4 | `geoLocationManager.getCurrentLocation` |
| `CONTACTS` | 3 | `contact.selectContacts`, `.queryContacts` |
| `SMS` | 5 | `telephony.sms.hasSmsCapability`, `.sendMessage` |
| `CLIPBOARD` | 3 | `pasteboard.getSystemPasteboard`, `.getData` |
| `CAMERA` | 2 | `multimedia.camera.getCameraManager` |
| `MICROPHONE` | 3 | `multimedia.audio.getAudioManager` |
| `SENSOR_DATA` | 2 | `sensor.on`, `sensor.once` |
| `ADVERTISING_ID` | 1 | `identifier.oaid.getOAID` |

---

## Output Format

### API Detection JSON (`results_*.json`)

```json
{
  "summary": {
    "total_detections": 43,
    "categories": ["ACCOUNT_INFO", "DEVICE_INFO", "NETWORK_INFO"],
    "total_functions_analyzed": 1248,
    "analysis_time_seconds": 0.4
  },
  "detections": [
    {
      "rule_id": "CLIPBOARD_002",
      "module": "@ohos:pasteboard",
      "method": "getData",
      "paradigm": "indirect_invoke",
      "category": "CLIPBOARD",
      "function_name": "com.example.app.pages.Clipboard.getClipboardData",
      "line_no": 4598,
      "context": "via getSystemPasteboard()"
    }
  ]
}
```

### Subgraph JSON (`subgraphs_*.json`)

```json
{
  "subgraphs": [
    {
      "id": "collab_0",
      "root": "com.example.app.DataCollector.collect",
      "privacy_categories": ["DEVICE_INFO", "NETWORK_INFO"],
      "source_nodes": ["@ohos:deviceInfo", "@ohos:wifiManager.getLinkedInfo"],
      "nodes": [
        {
          "name": "com.example.app.DataCollector.collect",
          "node_type": "internal",
          "is_root": true,
          "function_body": { "instructions": ["..."] }
        }
      ],
      "edges": [
        { "from": "...", "to": "...", "type": "internal_call" }
      ]
    }
  ]
}
```

### Subgraph DOT (`subgraphs_*.dot`)

Can be rendered into a visual graph using Graphviz:

```bash
dot -Tpng subgraphs_modules_20260225_152227.dot -o subgraphs.png
```

---

## How It Works

### Phase 1: Parsing (`parser.py`)

The parser uses a four-state machine to process `.pa` files:

```
INITIAL → TOP_LEVEL → IN_LITERAL_ARR / IN_FUNCTION
```

Extracted structures:
1. **ModuleLiteralArray** — contains `MODULE_REQUEST_ARRAY` and `ModuleTag` declarations.
2. **PaRecord** — named records with a `moduleRecordIdx` field.
3. **PaFunction** — named functions with their instruction sequences.

### Phase 2: Module Resolution (`resolver.py`)

For each function, the resolver finds the owning Record via longest-prefix matching, then follows `moduleRecordIdx` to build a `{local_name: module_request}` import map.

### Phase 3: In-function Detection (`detector.py`)

Uses a two-pass CFG analysis:

1. **Fixed-point iteration**: processes basic blocks in RPO order, propagates register states, and conservatively merges at join points.
2. **Detection pass**: using the converged register states, analyzes instructions one by one and matches `(module, method)` pairs.

### Phase 4: Call Graph Construction (`callgraph.py`)

Analyzes `definefunc`/`callthis*` instructions across all functions to build a global call graph:
- **Internal call edges**: function A calls function B via `definefunc` + `callthis*`.
- **External API edges**: a function calls a `@ohos:*` system module method.
- **Callback edges**: indirect calls via closure arguments.

### Phase 5: Sensitive Node Annotation (`subgraph.py` — phase 1)

Iterates all external API nodes in the call graph and matches them against the rule library. Matching nodes are marked as sensitive sources (`SensitiveNode`) with their matched rule ID and privacy category.

### Phase 6: Semantic-Root Backtracking + Lifecycle Context Collection (`subgraph.py` — phase 2)

**Core idea**: starting from the direct callers of sensitive APIs, perform reverse BFS to find HarmonyOS lifecycle entry functions or graph roots. This determines *who triggers the behavior and in what context*. At the same time, all lifecycle methods in the same module are collected as context metadata.

Algorithm:

1. **Collect start points**: find all internal functions that directly call a sensitive API.
2. **Reverse BFS**: from each start point, traverse `incoming` edges upward (maximum depth: 15 hops).
3. **Hit conditions** — in priority order:
   - **Lifecycle method** (preferred): matches the `_LIFECYCLE_PATTERNS` allowlist (`onCreate`, `onForeground`, `build`, `onClick`, `onMessage`, and 30+ other keywords).
   - **Graph root** (fallback): a function with no callers is used as the logical entry point.
   - **Depth limit**: when the maximum backtracking depth is reached, the deepest node found so far is used.
4. **Aggregation**: sensitive sources that share the same semantic root are merged into one subgraph group.
5. **Lifecycle context collection**: by matching module-prefix from function fully-qualified names, all lifecycle methods under the same ViewPU class (such as `aboutToAppear`, `initialRender`, `onClick`, `onPageShow`) are found and attached as a `lifecycle_context` list in the subgraph metadata.

**Why lifecycle methods are not used as BFS roots:**

In ArkUI declarative framework, lifecycle methods such as `initialRender` and `aboutToAppear` reference component functions through the `ViewPU` registration mechanism rather than through explicit `callthis*` instructions. As a result, the call graph contains no edges from lifecycle methods to business functions. Using lifecycle methods as BFS roots would yield empty subgraphs due to missing paths. The design therefore separates concerns: the original direct callers serve as BFS roots (ensuring complete paths), while lifecycle methods are attached as metadata (providing trigger context).

### Phase 7: Bidirectional BFS Subgraph Extraction (`subgraph.py` — phase 3)

Starting from the semantic root node, the extraction performs bidirectional BFS over the call graph:
1. **Forward BFS**: from the root downward to find all reachable nodes.
2. **Reverse BFS**: from sensitive sources upward to find all reverse-reachable nodes.
3. **Intersection**: retain only nodes that are reachable in both directions.
4. **Attach function bodies**: for each internal function node, attach its full instruction sequence.
5. **Attach lifecycle context**: write the same-module lifecycle method list as `lifecycle_context` metadata into the subgraph JSON.

Example subgraph JSON output:
```json
{
  "root": "com.app.pages.deviceid.deviceid",
  "privacy_categories": ["DEVICE_INFO"],
  "lifecycle_context": [
    {"name": "...deviceid.initialRender", "method": "initialRender", "out_degree": 15},
    {"name": "...deviceid.aboutToBeDeleted", "method": "aboutToBeDeleted", "out_degree": 5}
  ]
}
```

### False-Positive Filtering

The `_IGNORED_METHODS` set filters out common non-privacy methods:

| Category | Methods |
|------|------|
| Promise chain | `then`, `catch`, `finally` |
| Logging | `log`, `error`, `info`, `warn`, `debug` |
| Resource cleanup | `off`, `unsubscribe`, `close`, `release`, `destroy` |

---

## Extensibility

### Adding New API Categories

1. Add rules to `rules/privacy_api_rules.yaml`.
2. No code changes required — the rule matcher dynamically indexes all rules at startup.

### Batch Analysis

```bash
for f in *.pa; do
    python main.py "$f"
done
```

Each run generates an independent timestamped report in the `output/` directory.

---

## Limitations

1. **Inter-function register tracking** — Register tracking resets at function boundaries. Cross-function data flow (e.g., module references passed as arguments) is handled indirectly via the call graph, but specific register values are not tracked across calls.
2. **CFG precision** — The CFG models explicit branches and try-catch structures. Indirect jumps via computed labels are not modeled.
3. **Conservative state merging** — At CFG join points, inconsistent register states default to `unknown`.
4. **Single-file scope** — Each `.pa` file is analyzed independently; cross-file references are not resolved.
5. **Declarative UI call-edge gaps** — In the ArkUI declarative framework, `initialRender` references component functions via the `ViewPU` registration mechanism rather than through `callthis*` instructions, so call edges between lifecycle methods and page logic functions may be missing.
6. **Rule completeness** — Detection quality depends on the rule set. New APIs will appear in `unmatched_calls` but will not generate detection results until rules are added.

---

## License

This project is released under the MIT License, built for HarmonyOS application security research and privacy compliance auditing.
