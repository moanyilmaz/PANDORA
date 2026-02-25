# PANDORA - 实现细节文档

PANDORA 是一款面向鸿蒙 (HarmonyOS) 应用的高性能静态分析引擎，在二进制层面审计应用的隐私合规性。通过解析 Panda Assembly (.pa) —— ArkTS/eTS 字节码的反汇编输出 —— PANDORA 无需获取源代码即可识别敏感系统 API 调用及其协同采集模式。

核心引擎基于 **控制流图 (CFG) 上的固定点寄存器状态机追踪** 进行函数内 API 检测，并通过 **全局调用图构建 + 语义根回溯（生命周期入口追溯）+ 同模块生命周期上下文标注** 实现跨函数的协同隐私采集子图提取。

## 目录

- [概述](#概述)
- [核心特性](#核心特性)
- [架构](#架构)
- [检测范式](#检测范式)
- [项目结构](#项目结构)
- [安装](#安装)
- [使用方法](#使用方法)
- [规则系统](#规则系统)
- [输出格式](#输出格式)
- [工作原理](#工作原理)
- [性能](#性能)
- [扩展方式](#扩展方式)
- [局限性](#局限性)

---

## 概述

鸿蒙应用被编译为 `.abc` (Ark Bytecode) 文件，可通过 `ark_disasm` 工具反汇编为 `.pa` (Panda Assembly) 文本格式。本分析器解析 `.pa` 文件，通过 **基于寄存器追踪的静态分析** 识别对隐私敏感系统 API 的调用（如位置、相机、联系人、设备标识符等），并进一步通过 **调用图分析** 识别多个隐私 API 的协同调用模式。

与简单的字符串匹配方法不同，本工具理解鸿蒙字节码中的四种不同 API 调用范式，使用寄存器状态机在指令序列中精确追踪模块引用，并构建跨函数的调用图来发现协同隐私采集。

### 动机

隐私合规审计通常需要：
1. **源代码** — 对第三方应用通常不可用
2. **动态分析** — 需要设备检测，可能遗漏不常执行的代码路径
3. **二进制分析** — 可以分析任何编译后的应用，无需源代码

本工具实现方法 (3)，提供自动化、可扩展的二进制级隐私 API 检测与协同分析。

---

## 核心特性

- **二进制级分析** — 直接分析编译后的 `.pa` 文件，无需源代码
- **四范式检测** — 处理直接调用、间接 (工厂) 链式调用、回调调用和常量属性访问
- **CFG 固定点分析** — 构建控制流图，含基本块分割、try→handler 边、寄存器状态收敛
- **字符串常量追踪** — 追踪 `lda.str` 值和链式属性访问（如 `sensor.SensorId.ACCELEROMETER`）
- **全局调用图** — 构建跨函数调用关系图，识别函数间调用链
- **语义根回溯** — 从敏感 API 逆向 BFS 追溯到 HarmonyOS 生命周期入口（如 `onCreate`、`onForeground`、`build`）或图根节点，定位行为触发的逻辑起点
- **生命周期上下文标注** — 收集同一 ViewPU 模块下所有生命周期方法（`aboutToAppear`、`initialRender`、`onClick` 等）作为 `lifecycle_context` 元数据附加到每个子图，供下游意图推断模块综合判断触发场景
- **深层调用链提取** — 从语义根 BFS 到敏感 API，提取完整调用路径，附带函数体
- **规则驱动检测** — 61 条可配置 YAML 规则覆盖 11+ 敏感 API 类别
- **误报过滤** — 自动过滤 Promise 链方法 (.then/.catch)、日志调用和资源清理操作
- **三格式输出** — 同时生成 JSON 检测报告、子图 JSON 和 Graphviz DOT 可视化
- **高性能** — 1,248 函数 + 16 子图分析约 0.4 秒

---

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                          main.py (CLI)                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐│
│  │ parser   │─>│ resolver │─>│ detector │  │   callgraph      ││
│  │          │  │          │  │          │  │   + subgraph      ││
│  │ .pa解析  │  │ 模块解析 │  │ API检测  │  │   协同子图提取   ││
│  └──────────┘  └──────────┘  └──────────┘  └────────┬─────────┘│
│                                                      │          │
│                                              ┌───────┴────────┐ │
│                                              │ rules/*.yaml   │ │
│                                              └────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│  output/results_*.json       API 检测报告                       │
│  output/subgraphs_*.json     隐私子图 (带函数体)                │
│  output/subgraphs_*.dot      隐私子图 (Graphviz 可视化)         │
└─────────────────────────────────────────────────────────────────┘
```

### 处理流程

```
.pa 文件 ──► 解析 (Literals, Records, Functions)
                       │
                       ▼
             模块解析 (Record → LiteralArray → Import Map)
                       │
              ┌────────┴────────┐
              ▼                 ▼
     函数内寄存器追踪     全局调用图构建
     + 规则匹配            (callgraph.py)
              │                 │
              ▼                 ▼
     results_*.json      1. 敏感节点标注
                         2. 语义根回溯 (逆向BFS→生命周期入口)
                         3. BFS 子图提取 + 函数体附加
                                │
                                ▼
                        subgraphs_*.json
                        subgraphs_*.dot
```

---

## 检测范式

本工具识别鸿蒙字节码中四种不同的隐私 API 调用模式：

### 1. 间接调用 (工厂模式)

工厂方法先获取服务实例，然后在该实例上调用实际的数据访问方法。

**源码等价：**
```typescript
let pasteboard = pasteboard.getSystemPasteboard();  // 工厂方法
let data = pasteboard.getData();                     // 数据访问
```

**二进制指令：**
```
ldexternalmodulevar 0x2
throw.undefinedifholewithname "pasteboard"
sta v5
lda v5
ldobjbyname 0x0, "getSystemPasteboard"    ◄─ 工厂方法
callthis0 0x2, v5                          ◄─ 返回实例
sta v6
lda v6
ldobjbyname 0x0, "getData"                ◄─ 数据访问
callthis0 0x4, v6                          ◄─ 实际调用
```

**检测机制：** 寄存器追踪器维护 `call_result` 状态及原始模块归属，使链式 `.getData()` 调用可被检测并标注上下文 `"via getSystemPasteboard()"`。

### 2. 直接调用

模块方法直接调用，无需中间实例。

```
ldexternalmodulevar 0x3
ldobjbyname 0x0, "getCurrentLocation"     ◄─ 属性访问
callthis1 0x2, v4, v5                     ◄─ 直接调用
```

### 3. 回调调用

回调函数作为参数传入 API 方法。

```
definefunc 0x6, ...                          ◄─ 回调定义
sta v7                                       ◄─ v7 = 闭包
ldobjbyname 0x0, "on"
callthis3 0x8, v5, v6, v7, v8               ◄─ v7 是闭包参数
```

### 4. 常量属性访问

模块级常量的只读访问，无方法调用。

```
ldexternalmodulevar 0x0
ldobjbyname 0x0, "productModel"            ◄─ 属性读取
sta v4                                      ◄─ 下一条非 call* 指令
```

---

## 项目结构

```
pa-privacy-analyzer/
├── main.py                          # CLI 入口 — 解析→检测→调用图→子图→输出
│
├── pandora/                         # 核心逻辑层
│   └── core/
│       ├── parser.py                # .pa 文件解析 (状态机: Literals→Records→Methods)
│       ├── resolver.py              # 模块解析 (Record→LiteralArray→Import Map)
│       ├── cfg.py                   # 控制流图构建 (基本块+异常边+RPO)
│       ├── detector.py              # 寄存器追踪检测引擎 (四范式)
│       ├── callgraph.py             # 全局调用图构建 (函数间调用边提取)
│       └── subgraph.py              # 协同子图提取 (语义根回溯+BFS)
│
├── rules/
│   └── privacy_api_rules.yaml       # 61+ 条隐私 API 检测规则
│
├── docs/
│   └── implementation_details.md    # 本文档
│
├── requirements.txt                 # Python 依赖 (pyyaml)
│
└── output/                          # 自动生成的输出目录
    ├── results_<name>_<ts>.json     # API 检测结果
    ├── subgraphs_<name>_<ts>.json   # 隐私子图 (JSON)
    └── subgraphs_<name>_<ts>.dot    # 隐私子图 (DOT 可视化)
```

### 模块详细

| 模块 | 说明 |
|------|------|
| `parser.py` | 状态机解析器，提取 `ModuleLiteralArray`、`PaRecord`、`PaFunction` |
| `resolver.py` | 通过最长前缀匹配将函数→Record→LiteralArray 建立 `{local_name: "@ohos:module"}` 导入映射 |
| `cfg.py` | 轻量级 CFG 构建：基本块分割、显式/隐式边、RPO 计算 |
| `detector.py` | 核心检测引擎：`RegisterTracker` (ACC+寄存器状态机)、`RuleMatcher` (索引查找)、`ApiDetector` (指令级分析) |
| `callgraph.py` | 全局调用图：分析 `definefunc`/`callthis*` 指令，构建跨函数调用边，支持内部调用/外部 API 调用/回调调用 |
| `subgraph.py` | 三阶段子图提取：(1) 敏感节点标注 (2) 语义根回溯 — 逆向 BFS 到生命周期入口或图根 + 同模块生命周期上下文收集 (3) 双向 BFS 子图提取 + 函数体附加 + `lifecycle_context` 元数据 |
| `main.py` | CLI 入口：协调全流程，生成 3 种输出文件 |

---

## 安装

### 前置条件

- **Python 3.10+** (使用 `match` 语法和类型联合 `|`)
- **PyYAML** 解析规则文件

### 安装步骤

```bash
cd pa-privacy-analyzer
pip install -r requirements.txt
```

### 获取 `.pa` 文件

```bash
ark_disasm input.abc output.pa
```

`ark_disasm` 工具是 [ArkCompiler Runtime Core](https://gitee.com/openharmony/arkcompiler_runtime_core) 工具链的一部分。

---

## 使用方法

### 基本用法

```bash
# 默认: JSON 输出到 output/ 目录 (同时生成 results + subgraphs + DOT)
python main.py path/to/modules.pa

# 纯 API 检测模式 (跳过子图提取，更快)
python main.py path/to/modules.pa --no-subgraph

# 表格输出到控制台
python main.py path/to/modules.pa --format table

# 自定义输出目录
python main.py path/to/modules.pa -o custom_output/

# 详细模式
python main.py path/to/modules.pa -v

# 自定义规则文件
python main.py path/to/modules.pa --rules custom_rules.yaml
```

### 输出文件命名

JSON 输出自动保存到 `output/` 目录，命名规则：

```
output/results_<pa_file_stem>_<YYYYMMDD_HHMMSS>.json
output/subgraphs_<pa_file_stem>_<YYYYMMDD_HHMMSS>.json
output/subgraphs_<pa_file_stem>_<YYYYMMDD_HHMMSS>.dot
```

三个文件使用同一时间戳，确保对应关系。

### 命令行参数

| 参数 | 说明 | 默认 |
|------|------|------|
| `pa_file` | .pa 文件路径 | (必需) |
| `--format` | 输出格式: `json` 或 `table` | `json` |
| `-o, --output` | 输出目录 | `output/` |
| `--rules` | 自定义 YAML 规则文件 | `rules/privacy_api_rules.yaml` |
| `--no-subgraph` | 跳过调用图构建和子图提取 | `false` |
| `-v, --verbose` | 显示详细解析信息 | `false` |

---

## 规则系统

规则定义在 `rules/privacy_api_rules.yaml` 中，使用声明式 YAML 格式。

### 规则结构

```yaml
rules:
  - id: "CLIPBOARD_001"
    module: "@ohos:pasteboard"
    method: "getSystemPasteboard"
    paradigm: "indirect_invoke"
    category: "CLIPBOARD"
    description: "Get system pasteboard service instance"
```

### 支持的类别

| 类别 | 规则数 | 典型 API |
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

## 输出格式

### API 检测 JSON (results_*.json)

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

### 子图 JSON (subgraphs_*.json)

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

### 子图 DOT (subgraphs_*.dot)

可使用 Graphviz 渲染为可视化图：

```bash
dot -Tpng subgraphs_modules_20260225_152227.dot -o subgraphs.png
```

---

## 工作原理

### 阶段 1: 解析 (`parser.py`)

解析器使用四状态机处理 `.pa` 文件：

```
INITIAL → TOP_LEVEL → IN_LITERAL_ARR / IN_FUNCTION
```

提取结构：
1. **ModuleLiteralArray** — 包含 `MODULE_REQUEST_ARRAY` 和 `ModuleTag` 声明
2. **PaRecord** — 带 `moduleRecordIdx` 字段的命名记录
3. **PaFunction** — 带指令序列的命名函数

### 阶段 2: 模块解析 (`resolver.py`)

为每个函数通过最长前缀匹配找到所属 Record，跟随 `moduleRecordIdx` 构建 `{local_name: module_request}` 导入映射。

### 阶段 3: 函数内检测 (`detector.py`)

使用两阶段 CFG 分析：

1. **固定点迭代**：按 RPO 序处理基本块，传播寄存器状态，在汇合点保守合并
2. **检测遍历**：使用收敛状态，逐指令分析，匹配 `(module, method)` 对

### 阶段 4: 调用图构建 (`callgraph.py`)

分析所有函数中的 `definefunc`/`callthis*` 指令，构建全局调用图：
- **内部调用边**：函数 A 通过 `definefunc` + `callthis*` 调用函数 B
- **外部 API 边**：函数调用 `@ohos:*` 系统模块方法
- **回调边**：通过闭包参数传递间接调用

### 阶段 5: 敏感节点标注 (`subgraph.py` 阶段一)

遍历调用图中所有外部 API 节点，与规则库进行匹配。命中的节点标记为敏感源（SensitiveNode），记录匹配规则 ID 和隐私类别。

### 阶段 6: 语义根回溯 + 生命周期上下文收集 (`subgraph.py` 阶段二)

**核心思路**：从敏感 API 的直接调用者逆向 BFS，追溯到 HarmonyOS 生命周期入口函数或图根节点，获得 **"谁在什么上下文中触发了这个行为"** 的语义信息。同时收集同模块下所有生命周期方法作为上下文元数据。

算法流程：

1. **收集起点**：找到所有直接调用敏感 API 的内部函数
2. **逆向 BFS**：从每个起点沿 `incoming` 边向上搜索（最大深度 15 层）
3. **命中判定** — 按优先级：
   - **生命周期方法** (最优)：命中 `_LIFECYCLE_PATTERNS` 白名单（`onCreate`、`onForeground`、`build`、`onClick`、`onMessage` 等 30+ 关键词）
   - **图根节点** (兜底)：无调用者的函数作为逻辑入口
   - **深度上限**：达到最大回溯深度时取当前最远节点
4. **聚合分组**：共享同一语义根的敏感源合并为一个子图组
5. **生命周期上下文收集**：通过函数全限定名的模块前缀匹配，找到同一 ViewPU 类下的所有生命周期方法（如 `aboutToAppear`、`initialRender`、`onClick`、`onPageShow` 等），作为 `lifecycle_context` 列表附加到子图元数据

**为什么不将生命周期方法作为 BFS 根**：

ArkUI 声明式框架中，`initialRender`/`aboutToAppear` 等生命周期方法通过 `ViewPU` 注册机制引用组件函数，而非通过 `callthis*` 指令直接调用。因此调用图中 **不存在从生命周期方法到业务函数的调用边**，如果将生命周期方法作为 BFS 根，双向 BFS 会因无路径而产出空子图。因此采用**两层分离设计**：原始调用者作为 BFS 根（保证路径完整），生命周期方法作为元数据标注（提供触发上下文）。

### 阶段 7: 双向 BFS 子图提取 (`subgraph.py` 阶段三)

从语义根节点出发，双向 BFS 遍历调用图：
1. **正向 BFS**：从根向下找所有可达节点
2. **反向 BFS**：从敏感源向上找所有可逆达节点
3. **取交集**：保留同时在正向和反向可达集合中的节点
4. **附加函数体**：为每个内部函数节点附加完整的指令序列
5. **附加生命周期上下文**：将同模块生命周期方法列表作为 `lifecycle_context` 元数据写入子图 JSON

输出子图 JSON 示例：
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

### 误报过滤

`_IGNORED_METHODS` 集合过滤常见非隐私方法：

| 类别 | 方法 |
|------|------|
| Promise 链 | `then`, `catch`, `finally` |
| 日志 | `log`, `error`, `info`, `warn`, `debug` |
| 资源清理 | `off`, `unsubscribe`, `close`, `release`, `destroy` |

---

## 扩展方式

### 添加新 API 类别

1. 在 `rules/privacy_api_rules.yaml` 中添加规则
2. 无需代码修改 — 规则匹配器在启动时动态索引所有规则

### 批量分析

```bash
for f in *.pa; do
    python main.py "$f"
done
```

每次运行会在 `output/` 目录生成独立的带时间戳的报告。

---

## 局限性

1. **函数间寄存器追踪** — 寄存器追踪在函数边界重置。跨函数数据流（如模块引用作为参数传递）由调用图间接处理，但不追踪具体寄存器值
2. **CFG 精度** — CFG 建模显式分支和 try-catch 结构。通过计算标签的间接跳转不建模
3. **保守状态合并** — 在 CFG 汇合点，不一致的寄存器状态默认为 `unknown`
4. **单文件范围** — 每个 `.pa` 文件独立分析，多文件间引用不解析
5. **声明式 UI 调用边缺失** — ArkUI 声明式框架中 `initialRender` 通过 `ViewPU` 注册机制引用组件函数，而非通过 `callthis*` 指令调用，导致生命周期方法与页面逻辑函数之间的调用边可能缺失
6. **规则完整性** — 检测质量依赖规则集。新 API 会出现在 `unmatched_calls` 但不会生成检测结果

---

## License

本项目在 MIT License 下发布，用于鸿蒙应用安全研究和隐私合规审计。
