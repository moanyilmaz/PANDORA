# PANDORA: Panda Assembly Navigation for Detection of Opcode-level Rights Access

PANDORA is a high-performance static analysis engine designed to audit privacy compliance in HarmonyOS applications at the binary level. By navigating through Panda Assembly (.pa)—the disassembled output of ArkTS/eTS bytecode—PANDORA identifies sensitive system API calls without requiring access to original source code.

At its core, PANDORA implements a fixed-point register tracking state machine over a Control Flow Graph (CFG), enabling it to resolve complex API invocation paradigms that simple pattern matching misses.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Detection Paradigms](#detection-paradigms)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Rule System](#rule-system)
- [Output Format](#output-format)
- [How It Works](#how-it-works)
- [Performance](#performance)
- [Extending the Tool](#extending-the-tool)
- [Limitations](#limitations)
- [License](#license)

---

## Overview

HarmonyOS applications are compiled into `.abc` (Ark Bytecode) files, which can be disassembled into `.pa` (Panda Assembly) text format using the `ark_disasm` tool. This analyzer parses `.pa` files to identify calls to privacy-sensitive system APIs (e.g., location, camera, contacts, device identifiers) through **register-tracking-based static analysis**.

Unlike simple string matching approaches, this tool understands the four distinct API invocation paradigms present in HarmonyOS bytecode and uses a register state machine to accurately trace module references through instruction sequences.

### Motivation

Privacy compliance auditing of mobile applications typically requires:
1. **Source code** — often unavailable for third-party apps
2. **Dynamic analysis** — requires device instrumentation and may miss infrequently executed code paths
3. **Binary analysis** — can analyze any compiled application without source access

This tool implements approach (3), providing automated, scalable privacy API detection at the binary level.

---

## Key Features

- **Binary-level analysis** — Works on compiled `.pa` files, no source code needed
- **Four paradigm detection** — Handles direct calls, indirect (factory) chains, callbacks, and constant property access
- **CFG-based analysis** — Constructs Control Flow Graphs with basic block splitting, try→handler edges, and fixed-point register state convergence
- **String constant tracking** — Tracks `lda.str` values and chained property access (e.g., `sensor.SensorId.ACCELEROMETER`)
- **Rule-based detection** — 61 configurable YAML rules covering 13+ sensitive API categories
- **False positive filtering** — Automatically filters Promise chain methods (`.then()/.catch()`), logging calls, and resource cleanup operations
- **Fast execution** — Analyzes 1,248 functions in ~0.2 seconds
- **Structured output** — JSON reports with 100% context coverage (data sinks, event types, call chains)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          main.py (CLI)                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐   ┌──────────────────┐   ┌────────────────┐   │
│  │ pa_parser.py │──>│module_resolver.py│──>│ api_detector.py│   │
│  │              │   │                  │   │                │   │
│  │ Parse .pa    │   │ Record→Literal   │   │ Register Track │   │
│  │ into structs │   │ Array mapping    │   │ + Rule Match   │   │
│  └──────────────┘   └──────────────────┘   └───────┬────────┘   │
│                                                    │            │
│                                             ┌──────┴───────┐    │
│                                             │ rules/*.yaml │    │
│                                             │              │    │
│                                             └──────────────┘    │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                    output/results_*.json                        │
└─────────────────────────────────────────────────────────────────┘
```

### Processing Pipeline

```
.pa file  ──►  Parse (Literals, Records, Functions)
                        │
                        ▼
              Module Resolution (Record → LiteralArray → Import Map)
                        │
                        ▼
              Register Tracking + Instruction Simulation
                        │
                        ▼
                  Rule Matching
                        │
                        ▼
                JSON/Table Report
```

---

## Detection Paradigms

The tool recognizes four distinct patterns of privacy API invocation in HarmonyOS bytecode:

### 1. Indirect Invoke (Factory Pattern)

A factory method first obtains a service instance, then the actual data-accessing method is called on that instance.

**Source-level pattern:**
```typescript
let pasteboard = pasteboard.getSystemPasteboard();  // Factory
let data = pasteboard.getData();                     // Actual data access
```

**Binary-level pattern:**
```
ldexternalmodulevar 0x2
throw.undefinedifholewithname "pasteboard"
sta v5
lda v5
ldobjbyname 0x0, "getSystemPasteboard"    ◄─ Factory method
callthis0 0x2, v5                          ◄─ Returns instance
sta v6
lda v6
ldobjbyname 0x0, "getData"                ◄─ Data access on instance
callthis0 0x4, v6                          ◄─ Actual call
```

**Detection:** The register tracker maintains `call_result` state with the original module attribution, enabling detection of the chained `.getData()` call with context `"via getSystemPasteboard()"`.

### 2. Direct Invoke

The module method is called directly without an intermediate instance.

**Source-level pattern:**
```typescript
let location = geoLocationManager.getCurrentLocation(requestInfo);
```

**Binary-level pattern:**
```
ldexternalmodulevar 0x3
throw.undefinedifholewithname "geoLocationManager"
sta v4
lda v4
ldobjbyname 0x0, "getCurrentLocation"     ◄─ Property access
callthis1 0x2, v4, v5                     ◄─ Direct call
```

### 3. Callback Invoke

A callback function is passed as an argument to the API method.

**Source-level pattern:**
```typescript
sensor.on(sensor.SensorId.ACCELEROMETER, (data) => {
    console.log(data.x, data.y, data.z);
});
```

**Binary-level pattern:**
```
ldexternalmodulevar 0x1
throw.undefinedifholewithname "sensor"
sta v5
lda v5
ldobjbyname 0x0, "SensorId"                ◄─ Chained property (level 1)
ldobjbyname 0x4, "ACCELEROMETER"            ◄─ Chained property (level 2)
sta v6                                       ◄─ v6 = property_access(sensor, ACCELEROMETER)
definefunc 0x6, ...                          ◄─ Callback definition
sta v7                                       ◄─ v7 = closure
lda v5
ldobjbyname 0x0, "on"
callthis3 0x8, v5, v6, v7, v8               ◄─ v6 is event type, v7 is closure
```

**Detection:** The tracker identifies `definefunc` → `sta` as a closure, and chained `ldobjbyname` on `property_access` preserves the module attribution (e.g., `ACCELEROMETER`). The callback event type is extracted to produce context `"listener: ACCELEROMETER"`.

### 4. Constant Access

Module-level constants are read without any method call — just a property access.

**Source-level pattern:**
```typescript
let model = deviceInfo.productModel;
let serial = deviceInfo.serial;
```

**Binary-level pattern:**
```
ldexternalmodulevar 0x0
throw.undefinedifholewithname "deviceInfo"
ldobjbyname 0x0, "productModel"            ◄─ Property read
sta v4                                      ◄─ Next opcode is NOT call*
```

**Detection:** When `ldobjbyname` is encountered on a `module_ref` and the next effective opcode is **not** a `call*` instruction, the access is classified as `constant_access`.

---

## Project Structure

```
pa-privacy-analyzer/
├── main.py               # CLI entry point — orchestrates parse → detect → output
├── pa_parser.py          # Three-phase .pa file parser (Literals → Records → Methods)
├── module_resolver.py    # Maps functions to their module import tables
├── api_detector.py       # Register-tracking detection engine (4 paradigms)
├── requirements.txt      # Python dependencies (pyyaml)
├── rules/
│   └── privacy_api_rules.yaml   # 61 detection rules across 13+ categories
└── output/               # Auto-generated output directory
    └── results_<name>_<timestamp>.json
```

### Module Details

| Module | Description |
|--------|-------------|
| `pa_parser.py` | State-machine parser that extracts `ModuleLiteralArray` (with `MODULE_REQUEST_ARRAY`), `PaRecord` (with `moduleRecordIdx`), and `PaFunction` (with instruction sequences) from `.pa` files |
| `module_resolver.py` | Links functions → Records → LiteralArrays to build `{local_name: "@ohos:module"}` import maps via longest-prefix matching |
| `api_detector.py` | Core detection engine with `RegisterTracker` (ACC + register state simulation), `RuleMatcher` (indexed lookup), and `ApiDetector` (instruction-by-instruction analysis) |
| `main.py` | CLI interface with JSON/table output formatting, auto-named output files |

---

## Installation

### Prerequisites

- **Python 3.10+** (uses `match` syntax and type union `|`)
- **PyYAML** for rule file parsing

### Setup

```bash
cd pa-privacy-analyzer
pip install -r requirements.txt
```

### Obtaining `.pa` Files

`.pa` files are generated from HarmonyOS `.abc` bytecode files using the `ark_disasm` disassembler:

```bash
ark_disasm input.abc output.pa
```

The `ark_disasm` tool is part of the [ArkCompiler Runtime Core](https://gitee.com/openharmony/arkcompiler_runtime_core) toolchain.

---

## Usage

### Basic Usage

```bash
# Default: JSON output saved to output/ directory
python main.py path/to/modules.pa

# Table output to console
python main.py path/to/modules.pa --format table

# Custom output directory
python main.py path/to/modules.pa -o custom_output/

# Verbose mode (shows parsing details)
python main.py path/to/modules.pa -v

# Custom rules file
python main.py path/to/modules.pa --rules custom_rules.yaml
```

### Output File Naming

JSON output is automatically saved to the `output/` directory with the naming convention:

```
output/results_<pa_file_stem>_<YYYYMMDD_HHMMSS>.json
```

For example:
```
output/results_modules_20260212_192305.json
```

### Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `pa_file` | Path to the `.pa` file to analyze | (required) |
| `--format` | Output format: `json` or `table` | `json` |
| `-o, --output` | Output directory path | `output/` |
| `--rules` | Path to custom YAML rules file | `rules/privacy_api_rules.yaml` |
| `-v, --verbose` | Show verbose parsing information | `false` |

---

## Rule System

Rules are defined in `rules/privacy_api_rules.yaml` using a declarative YAML format.

### Rule Structure

```yaml
rules:
  - id: "CLIPBOARD_001"            # Unique rule identifier
    module: "@ohos:pasteboard"      # HarmonyOS module name (@ohos: prefix)
    method: "getSystemPasteboard"   # Method or property name to detect
    paradigm: "indirect_invoke"     # Expected invocation paradigm
    category: "CLIPBOARD"           # Privacy category classification
    description: "Get system pasteboard service instance"
```

### Supported Categories

| Category | # Rules | Example APIs |
|----------|---------|-------------|
| `DEVICE_INFO` | 12 | `deviceInfo.deviceType`, `.serial`, `.productModel`, `.brand` |
| `ACCOUNT_INFO` | 8 | `osAccount.getAccountManager`, `appAccount.getAllAccounts` |
| `NETWORK_INFO` | 8 | `wifiManager.getLinkedInfo`, `net.connection.getDefaultNet` |
| `PRECISE_LOCATION` | 4 | `geoLocationManager.getCurrentLocation`, `.getLastLocation` |
| `CONTACTS` | 3 | `contact.selectContacts`, `.queryContacts` |
| `SMS` | 5 | `telephony.sms.hasSmsCapability`, `.sendMessage` |
| `CLIPBOARD` | 3 | `pasteboard.getSystemPasteboard`, `.getData` |
| `CAMERA` | 2 | `multimedia.camera.getCameraManager` |
| `MICROPHONE` | 3 | `multimedia.audio.getAudioManager`, `.createAudioCapturer` |
| `SENSOR_DATA` | 2 | `sensor.on`, `sensor.once` |
| `BLUETOOTH` | 3 | `bluetooth.access.getState`, `.on` |
| `ADVERTISING_ID` | 1 | `identifier.oaid.getOAID` |

### Paradigm Types

| Paradigm | Description | Example |
|----------|-------------|---------|
| `indirect_invoke` | Factory pattern: obtain instance, then call method | `pasteboard.getSystemPasteboard()` → `.getData()` |
| `direct_invoke` | Direct module method call | `geoLocationManager.getCurrentLocation()` |
| `callback_invoke` | Method call with callback function argument | `sensor.on(type, callback)` |
| `constant_access` | Read-only property access (no method call) | `deviceInfo.serial` |

### Adding Custom Rules

To add a new detection rule, append to `rules/privacy_api_rules.yaml`:

```yaml
  - id: "CUSTOM_001"
    module: "@ohos:your.module"
    method: "sensitiveMethod"
    paradigm: "direct_invoke"
    category: "CUSTOM_CATEGORY"
    description: "Description of what this API accesses"
```

---

## Output Format

### JSON Output

```json
{
  "summary": {
    "total_detections": 43,
    "total_unmatched": 0,
    "categories": ["ACCOUNT_INFO", "DEVICE_INFO", "NETWORK_INFO", ...],
    "total_functions_analyzed": 1248,
    "total_records": 32,
    "analysis_time_seconds": 0.196
  },
  "detections": [
    {
      "rule_id": "CLIPBOARD_002",
      "module": "@ohos:pasteboard",
      "method": "getData",
      "paradigm": "indirect_invoke",
      "category": "CLIPBOARD",
      "description": "Read clipboard data (requires instance first)",
      "function_name": "com.example.app.pages.Clipboard.getClipboardData",
      "line_no": 4598,
      "context": "via getSystemPasteboard()"
    }
  ],
  "unmatched_calls": []
}
```

### Detection Fields

| Field | Description |
|-------|-------------|
| `rule_id` | Matched rule identifier (e.g., `CLIPBOARD_002`) |
| `module` | HarmonyOS system module (e.g., `@ohos:pasteboard`) |
| `method` | Called method or accessed property |
| `paradigm` | Detected invocation paradigm |
| `category` | Privacy category |
| `function_name` | Fully qualified function name where the call was found |
| `line_no` | Line number in the `.pa` file |
| `context` | Contextual info: factory chain, data sink, callback event type |

### Context Field

The `context` field provides 100% coverage — every detection has contextual information. The context is generated through multiple techniques:

| Context Type | Example | How it's generated |
|-------------|---------|-------------------|
| Factory chain | `"via getSystemPasteboard()"` | Traces `call_result` state to identify the factory method |
| Callback event | `"listener: ACCELEROMETER"` | Extracts chained property access or string constant from callback arguments |
| Data sink | `"result -> .then()"` / `"stored to .wifiInfo"` | Forward-scans ~20 instructions, skipping async/generator noise |
| Return tracking | `"returned"` | Detects when result flows to a `return` instruction |
| Page fallback | `"in page: sensor"` | Extracts page name from fully qualified function name |

### Unmatched Calls

The `unmatched_calls` section reports API calls on sensitive modules that were detected by the register tracker but did not match any rule. This helps identify:
- APIs that should be added to the rule set
- New or undocumented HarmonyOS APIs

**Note:** Common false-positive sources (Promise chain methods like `.then()/.catch()`, logging methods like `.log()/.error()`, and resource cleanup methods like `.off()/.close()`) are automatically filtered and will not appear in the unmatched list.

---

## How It Works

### Phase 1: Parsing (`pa_parser.py`)

The parser uses a state machine with four states to process the `.pa` file:

```
INITIAL → TOP_LEVEL → IN_LITERAL_ARR / IN_FUNCTION
```

**Extracted structures:**

1. **ModuleLiteralArray** — Contains `MODULE_REQUEST_ARRAY` entries and `ModuleTag` declarations (`REGULAR_IMPORT`, `LOCAL_EXPORT`), linking local variable names to `@ohos:*` module paths
2. **PaRecord** — Named records with `moduleRecordIdx` fields pointing to a ModuleLiteralArray's hex address
3. **PaFunction** — Named functions with their instruction sequences (opcode + operands + line numbers)

### Phase 2: Module Resolution (`module_resolver.py`)

For each function, the resolver:
1. Finds the owning `PaRecord` via **longest-prefix matching** on the fully qualified function name
2. Follows the record's `moduleRecordIdx` to the corresponding `ModuleLiteralArray`
3. Builds a `{local_name: module_request}` import map from `REGULAR_IMPORT` entries

**Example mapping:**
```python
{
    "pasteboard": "@ohos:pasteboard",
    "sensor": "@ohos:sensor",
    "deviceInfo": "@ohos:deviceInfo"
}
```

### Phase 3: Detection (`api_detector.py`)

For each function with sensitive module imports, the detector uses a **two-phase CFG-based analysis**:

#### CFG Construction (`cfg.py`)
- Splits instructions into **basic blocks** at label targets, branch instructions, and terminators
- Builds explicit edges (conditional/unconditional jumps, fall-through)
- Builds implicit **try→handler edges** for exception flow (preserves register state across exceptions)
- Computes **reachable blocks** via BFS from entry + handler entries
- Generates **reverse postorder** traversal for optimal fixed-point iteration

#### Phase 1: Fixed-Point Iteration
- Processes blocks in RPO order, propagating register states (`RegisterTracker`)
- Merges predecessor states at join points (conservative: inconsistent → unknown)
- Handler blocks: inherits registers from predecessors but resets ACC (exception object)
- Iterates until all block output states converge (no changes)

#### Phase 2: Detection Traversal
- Uses converged states from Phase 1 as input to each block
- Walks instructions with `detect=True`, generating `ApiDetection` results
- At each `callthis*`, matches `(module, method)` against rule index
- Classifies paradigm based on register state:
   - Has `factory_method` → `indirect_invoke`
   - Has closure argument → `callback_invoke`
   - Default → `direct_invoke`

### False Positive Filtering

The `_IGNORED_METHODS` set filters out common non-privacy methods that would otherwise produce false positives:

| Category | Methods |
|----------|---------|
| Promise chain | `then`, `catch`, `finally` |
| Logging | `log`, `error`, `info`, `warn`, `debug` |
| Resource cleanup | `off`, `unsubscribe`, `close`, `release`, `destroy` |

These methods are excluded from both detection matching and unmatched call reporting.

---

## Extending the Tool

### Adding Support for New API Categories

1. **Add rules** to `rules/privacy_api_rules.yaml`
2. No code changes needed — the rule matcher dynamically indexes all rules at startup

### Supporting New Invocation Patterns

To add a new detection paradigm:

1. Add the pattern name to the `paradigm` field options in the rule schema
2. Implement detection logic in `ApiDetector._handle_call()` or `_analyze_function()`
3. Update the `RegisterTracker` if new state types are needed

### Analyzing Multiple Files

```bash
# Batch analysis using shell loop
for f in *.pa; do
    python main.py "$f"
done
```

Each run produces a separate timestamped JSON report in the `output/` directory.

---

## Limitations

1. **Intra-function analysis only** — The register tracker resets at function boundaries. Cross-function data flow (e.g., a module reference passed as a parameter) is not tracked.

2. **CFG precision** — The CFG models explicit branches and try-catch structures. Indirect jumps via computed labels or dynamically dispatched exceptions beyond try-catch are not modeled.

3. **Conservative state merging** — At CFG join points, inconsistent register states default to `unknown`. This is sound (no false negatives from merge) but may lose precision in deeply branched code.

4. **Single-file scope** — Each `.pa` file is analyzed independently. Inter-module references across multiple `.pa` files are not resolved.

5. **Rule completeness** — Detection quality depends on the rule set. New HarmonyOS APIs not yet covered by rules will appear as `unmatched_calls` but won't generate detections.

---

## License

This project is provided for research and educational purposes within the scope of HarmonyOS application privacy compliance analysis.
