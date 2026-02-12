# PANDORA: Panda Assembly Navigation for Detection of Opcode-level Rights Access

PANDORA is a high-performance static analysis engine designed to audit privacy compliance in HarmonyOS applications at the binary level. By navigating through Panda Assembly (.pa)—the disassembled output of ArkTS/eTS bytecode—PANDORA identifies sensitive system API calls without requiring access to original source code.

At its core, PANDORA implements a fixed-point register tracking state machine over a Control Flow Graph (CFG), enabling it to resolve complex API invocation paradigms that simple pattern matching misses.

## Key Capabilities

- **Zero-Source Auditing**: Analyze any compiled HarmonyOS .abc file (via ark_disasm) to verify third-party SDK behavior.
- **Deep Register Tracking**: Simulates the Accumulator (ACC) and register states to track module references across instruction sequences.
- **Four-Paradigm Detection**: Specifically engineered to handle the unique ways HarmonyOS invokes APIs:
    - **Indirect (Factory)**: Tracing instances returned by service getters.
    - **Direct**: Standard module method invocations.
    - **Callback**: Identifying sensitive data access within closures and event listeners.
    - **Constant Access**: Detecting passive data reads (e.g., deviceInfo properties).
- **Flow-Aware Precision**: Constructs a CFG with explicit branch modeling and implicit try-catch-handler edges to ensure analysis coverage in error-handling code.
- **Zero-Noise Filtering**: Built-in heuristics to ignore Promise chains (.then), logging, and resource cleanup, focusing only on actual data "sinks."

## Architecture

PANDORA operates through a multi-stage pipeline designed for both speed and accuracy:

1. **Parsing Phase**: A state-machine parser reconstructs the structure of .pa files, mapping ModuleLiteralArrays to their respective functions.
2. **Resolution Phase**: Links local namespace aliases to global HarmonyOS @ohos modules using longest-prefix record matching.
3. **Analysis Phase (The Engine)**:
    - **CFG Construction**: Dissects instructions into basic blocks.
    - **Fixed-Point Iteration**: Propagates register states across the graph until convergence.
    - **Pattern Synthesis**: Matches resolved calls against 61+ declarative rules.
4. **Reporting Phase**: Generates structured JSON or human-readable tables with 100% context coverage (e.g., "via factory," "in callback").

## Detection Paradigm Examples

The "Navigation" in Action
In HarmonyOS bytecode, a simple API call is often fragmented. PANDORA navigates these fragments:

```assembly
# Example: Indirect Invoke (Factory Pattern)
ldexternalmodulevar 0x2          # Load 'pasteboard' module
sta v5                           # Navigate module ref to v5
lda v5
ldobjbyname 0x0, "getSystem..."  # Identify Factory Method
callthis0 0x2, v5                # Tracking: result is now a 'pasteboard' instance
sta v6                           # Navigate instance to v6
...
lda v6
ldobjbyname 0x0, "getData"       # SINK DETECTED: via pasteboard instance
```

## Installation & Usage

### Prerequisites
- Python 3.10+
- ark_disasm (from ArkCompiler toolchain)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/moanyilmaz/PANDORA.git
cd PANDORA

# Install dependencies
pip install -r requirements.txt

# Run analysis
python main.py samples/target_app.pa --format table
```

## Rule System & Categories

PANDORA ships with a comprehensive suite of rules (rules/privacy_api_rules.yaml) covering:

| Category | Typical Scopes |
|----------|----------------|
| **IDENTITY** | OS Account, App Account, Advertising ID (OAID) |
| **LOCATION** | Precise/Coarse Geo-location, Geocoding |
| **MEDIA** | Camera, Audio Capturer (Microphone) |
| **NETWORK** | WiFi Info, Connection Stats, Bluetooth State |
| **HARDWARE** | Device Serial, Product Model, Sensor Data |
| **STORAGE** | Clipboard (Pasteboard), Contact Databases |

## Limitations

- **Intra-procedural**: Current navigation is limited to function boundaries.
- **Static Scope**: Does not account for runtime-only dynamic property injections.

## License

This project is released under the MIT License. Developed for HarmonyOS security research and privacy compliance auditing.
