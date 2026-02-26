# PANDORA: Panda Assembly Navigation for Detection of Opcode-level Rights Access

PANDORA is a high-performance static analysis engine for HarmonyOS applications. It audits privacy compliance at the binary level by parsing Panda Assembly (`.pa`) files, which are disassembled outputs of ArkTS/eTS bytecode. This allows PANDORA to detect sensitive system API usage without requiring application source code.

The core engine combines four key techniques: **fixed-point register-state tracking on CFGs**, **global call graph construction**, **semantic-root backtracking to lifecycle entry points**, and **same-module lifecycle context annotation**. Together, they provide an end-to-end pipeline from instruction-level in-function analysis to cross-function collaborative privacy collection discovery.

## Core Capabilities

- **Source-free auditing**: Analyze compiled HarmonyOS `.abc` artifacts (after `ark_disasm`) to inspect third-party SDK behavior.
- **Deep register tracking**: Simulate ACC and register states to track module references through instruction sequences.
- **Four-paradigm detection**: Handle four HarmonyOS API invocation styles:
    - **Indirect invocation (factory pattern)**: Track instances returned by service getters.
    - **Direct invocation**: Detect standard module method calls.
    - **Callback invocation**: Identify sensitive access inside closures and event listeners.
    - **Constant property access**: Detect passive data reads (for example, `deviceInfo` properties).
- **Cross-function collaborative analysis**: Build a global call graph to detect patterns where multiple privacy APIs are coordinated by shared upper-layer logic.
- **Semantic-root backtracking**: Reverse BFS from sensitive APIs to HarmonyOS lifecycle entries (such as `onCreate`, `onForeground`, `build`) or graph roots, yielding full triggering chains for intent inference.
- **Lifecycle context annotation**: Collect lifecycle methods from the same ViewPU module (such as `aboutToAppear`, `initialRender`, `onClick`) and attach them as `lifecycle_context` metadata for downstream scenario inference.
- **Deep call-chain extraction**: Extract complete paths from semantic roots to sensitive APIs, including function bodies.

## Architecture

The CLI entry point is `main.py`, which orchestrates the full analysis pipeline.

1. `parser` reads the `.pa` file and extracts literals, records, and functions.
2. `resolver` maps records to literal arrays and builds import maps for module resolution.
3. `detector` performs instruction-level sensitive API detection using register-state tracking and rule matching.
4. `callgraph` and `subgraph` collaborate to build the global call graph and extract collaborative privacy subgraphs.
5. `rules/*.yaml` provides the declarative rule base used by the detector.
6. The pipeline writes three output artifacts:
    - `output/results_*.json`: API detection report.
    - `output/subgraphs_*.json`: privacy subgraphs with function bodies and metadata.
    - `output/subgraphs_*.dot`: Graphviz visualization for the extracted subgraphs.

### Processing Flow

The analysis flow is as follows:

1. Parse the `.pa` file into structured entities (literals, records, functions).
2. Resolve module imports from `Record -> LiteralArray -> Import Map` relationships.
3. Run in-function register tracking plus rule matching to produce `results_*.json`.
4. Build a global call graph across functions.
5. Mark sensitive nodes in the graph.
6. Perform reverse BFS to semantic roots (typically lifecycle entry points), while collecting same-module lifecycle context.
7. Extract subgraphs with bidirectional BFS, attach function bodies, and add `lifecycle_context` metadata.
8. Emit `subgraphs_*.json` and `subgraphs_*.dot`.

## Installation & Usage

### Prerequisites
- Python 3.10+
- `ark_disasm` (from the ArkCompiler toolchain)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/moanyilmaz/PANDORA.git
cd PANDORA/pa-privacy-analyzer

# Install dependencies
pip install -r requirements.txt

# Run analysis (writes 3 files into `output/`)
python main.py path/to/modules.pa

# API-only mode (skip subgraph extraction for faster runs)
python main.py path/to/modules.pa --no-subgraph

# Print table format to stdout
python main.py path/to/modules.pa --format table
```

### Output Files

Each run generates three files with the same timestamp:

| File | Format | Content |
|------|------|------|
| `results_<name>_<ts>.json` | JSON | Function-level API detection results (rules, paradigms, context) |
| `subgraphs_<name>_<ts>.json` | JSON | Collaborative privacy subgraphs (with function bodies and call chains) |
| `subgraphs_<name>_<ts>.dot` | DOT | Graphviz visualization of extracted subgraphs |

### Command-Line Arguments

| Argument | Description | Default |
|------|------|------|
| `pa_file` | Path to the `.pa` file | (required) |
| `--format` | Output format: `json` or `table` | `json` |
| `-o, --output` | Output directory | `output/` |
| `--rules` | Custom YAML rule file | `rules/privacy_api_rules.yaml` |
| `--no-subgraph` | Skip subgraph extraction | `false` |
| `-v, --verbose` | Show verbose parsing details | `false` |

## Rule System & Categories

PANDORA ships with 61+ rules in `rules/privacy_api_rules.yaml`, covering:

| Category | Typical Scope |
|------|---------|
| **ACCOUNT_INFO** | OS accounts, app accounts |
| **ADVERTISING_ID** | OAID |
| **CAMERA** | Camera manager |
| **CLIPBOARD** | System pasteboard |
| **CONTACTS** | Contacts database |
| **DEVICE_INFO** | Device serial number, model, brand |
| **MICROPHONE** | Audio capture |
| **NETWORK_INFO** | Wi-Fi info, network connections |
| **PRECISE_LOCATION** | Precise / coarse geolocation |
| **SENSOR_DATA** | Sensor events |
| **SMS** | SMS capabilities |

## Limitations

- **Inter-function state**: Register tracking resets at function boundaries, so cross-function data flow (such as module references passed via parameters) is not tracked.
- **Single-file scope**: Each `.pa` file is analyzed independently; cross-file references are not resolved.
- **Declarative UI call-edge gaps**: In ArkUI declarative patterns, `initialRender` references component functions through `ViewPU` registration rather than explicit `callthis*` instructions, so some edges between lifecycle methods and page logic may be missing.

## License

MIT License. Built for HarmonyOS security research and privacy compliance auditing.
