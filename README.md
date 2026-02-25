# PANDORA: Panda Assembly Navigation for Detection of Opcode-level Rights Access

PANDORA 是一款面向鸿蒙 (HarmonyOS) 应用的高性能静态分析引擎，在二进制层面审计应用的隐私合规性。通过解析 Panda Assembly (.pa) —— ArkTS/eTS 字节码的反汇编输出 —— PANDORA 无需获取源代码即可识别敏感系统 API 调用。

核心引擎基于 **控制流图 (CFG) 上的固定点寄存器状态机追踪**、**全局调用图构建**、**语义根回溯（生命周期入口追溯）** 和 **同模块生命周期上下文标注** 四大技术，实现从函数内指令级分析到跨函数协同隐私采集识别的完整链路。

## 核心能力

- **零源码审计**：分析任意编译后的鸿蒙 .abc 文件（经 ark_disasm 反汇编），验证第三方 SDK 行为
- **深度寄存器追踪**：模拟累加器 (ACC) 和寄存器状态，在指令序列中追踪模块引用
- **四范式检测**：处理鸿蒙 API 调用的四种独特方式：
    - **间接调用 (工厂模式)**：追踪服务 getter 返回的实例
    - **直接调用**：标准模块方法调用
    - **回调调用**：识别闭包和事件监听器中的敏感数据访问
    - **常量属性访问**：检测被动数据读取（如 deviceInfo 属性）
- **跨函数协同分析**：构建全局调用图，识别多个隐私 API 被同一上层逻辑协同调用的模式
- **语义根回溯**：从敏感 API 逆向 BFS 追溯到 HarmonyOS 生命周期入口（如 `onCreate`、`onForeground`、`build`）或图根节点，产出完整调用链，为目的推断提供行为上下文
- **生命周期上下文标注**：收集同一 ViewPU 模块下所有生命周期方法（`aboutToAppear`、`initialRender`、`onClick` 等）作为 `lifecycle_context` 元数据附加到每个子图，供下游意图推断模块综合判断触发场景
- **深层调用链提取**：BFS 提取从语义根到敏感 API 的完整路径，附带函数体

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
│  output/results_*.json      API 检测报告                        │
│  output/subgraphs_*.json    隐私子图 (带函数体)                 │
│  output/subgraphs_*.dot     隐私子图 (Graphviz 可视化)          │
└─────────────────────────────────────────────────────────────────┘
```

### 处理流程

```
.pa 文件  ──►  解析 (Literals, Records, Functions)
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
                             + 同模块生命周期上下文收集
                          3. 双向 BFS 子图提取 + 函数体附加
                             + lifecycle_context 元数据
                                 │
                                 ▼
                          subgraphs_*.json
                          subgraphs_*.dot
```

## 安装 & 使用

### 前置条件
- Python 3.10+
- ark_disasm (ArkCompiler 工具链)

### 快速开始

```bash
# 克隆仓库
git clone https://github.com/moanyilmaz/PANDORA.git
cd PANDORA/pa-privacy-analyzer

# 安装依赖
pip install -r requirements.txt

# 运行分析（输出 3 个文件到 output/ 目录）
python main.py path/to/modules.pa

# 纯 API 检测模式（跳过子图提取，更快）
python main.py path/to/modules.pa --no-subgraph

# 表格输出到 stdout
python main.py path/to/modules.pa --format table
```

### 输出文件

一次运行生成 3 个同时间戳文件：

| 文件 | 格式 | 内容 |
|------|------|------|
| `results_<name>_<ts>.json` | JSON | 函数级 API 检测结果（规则、范式、上下文） |
| `subgraphs_<name>_<ts>.json` | JSON | 协同隐私子图（含函数体、调用链） |
| `subgraphs_<name>_<ts>.dot` | DOT | 子图可视化（Graphviz 渲染） |

### 命令行参数

| 参数 | 说明 | 默认 |
|------|------|------|
| `pa_file` | .pa 文件路径 | (必需) |
| `--format` | 输出格式: `json` 或 `table` | `json` |
| `-o, --output` | 输出目录 | `output/` |
| `--rules` | 自定义规则 YAML 文件 | `rules/privacy_api_rules.yaml` |
| `--no-subgraph` | 跳过子图提取 | `false` |
| `-v, --verbose` | 显示详细解析信息 | `false` |

## 规则系统 & 类别

PANDORA 内置 61+ 条规则 (`rules/privacy_api_rules.yaml`) 覆盖：

| 类别 | 典型范围 |
|------|---------|
| **ACCOUNT_INFO** | OS 账户、应用账户 |
| **ADVERTISING_ID** | OAID |
| **CAMERA** | 相机管理器 |
| **CLIPBOARD** | 系统剪贴板 |
| **CONTACTS** | 联系人数据库 |
| **DEVICE_INFO** | 设备序列号、型号、品牌 |
| **MICROPHONE** | 音频采集器 |
| **NETWORK_INFO** | WiFi 信息、网络连接 |
| **PRECISE_LOCATION** | 精确/粗略地理位置 |
| **SENSOR_DATA** | 传感器事件 |
| **SMS** | 短信能力 |

## 局限性

- **函数间状态**：寄存器追踪在函数边界重置，跨函数数据流（参数传递模块引用）不追踪
- **单文件范围**：每个 .pa 文件独立分析，多文件间引用不解析
- **声明式 UI 调用边缺失**：ArkUI 声明式框架中 `initialRender` 通过 `ViewPU` 注册机制引用组件函数，而非通过 `callthis*` 指令调用，导致生命周期方法与页面逻辑函数之间的调用边可能缺失

## License

MIT License. 为鸿蒙安全研究和隐私合规审计开发。
