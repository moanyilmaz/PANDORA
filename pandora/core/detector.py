"""
PANDORA Detection Engine (api_detector.py)
========================================
基于控制流图 (CFG) 和寄存器状态追踪，通过四种调用范式
识别 .pa 文件中的隐私敏感API调用。

分析流程:
  1. 构建 CFG (基本块 + 边)
  2. 固定点迭代: 在 RPO 顺序下传播寄存器状态至收敛
  3. 检测遍历: 基于收敛状态，在可达块中生成检测结果

四种范式:
  1. Indirect Invoke   - 工厂方法获取实例后调用 (pasteboard.getSystemPasteboard().getData())
  2. Direct Invoke     - 直接调用模块方法 (connection.getDefaultNet())
  3. Callback Invoke   - 回调方式调用 (identifier.getOAID(callback))
  4. Constant Access   - 读取模块常量属性 (deviceInfo.deviceType)
"""

import re
import yaml
from dataclasses import dataclass, field
from pathlib import Path

from .parser import PaFile, PaFunction, Instruction
from .resolver import ModuleResolver
from .cfg import ControlFlowGraph, BlockState, merge_states, _reg_to_tuple, _UNKNOWN_TUPLE


# ============================================================
# 数据结构
# ============================================================

@dataclass
class ApiDetection:
    """一次检测到的API调用"""
    rule_id: str            # 规则ID, e.g. "CLIPBOARD_001"
    module: str             # 模块名, e.g. "@ohos:pasteboard"
    method: str             # 方法/属性名, e.g. "getSystemPasteboard"
    paradigm: str           # 检测到的范式类型
    category: str           # 隐私类别
    description: str        # 规则描述
    function_name: str      # 所在函数完全限定名
    line_no: int            # 在.pa文件中的行号
    context: str = ""       # 上下文信息 (调用链/数据去向/事件类型)


@dataclass
class UnmatchedApiCall:
    """检测到的模块方法调用但未匹配到规则"""
    module: str
    method: str
    function_name: str
    line_no: int


# ============================================================
# 寄存器跟踪
# ============================================================

@dataclass
class RegState:
    """寄存器/ACC 的状态"""
    kind: str = "unknown"     # "module_ref", "property_access", "call_result", "closure", "string_const", "unknown"
    module: str = ""          # 关联的模块名
    method: str = ""          # 关联的方法/属性名
    factory_module: str = ""  # (indirect) 工厂方法所属模块
    factory_method: str = ""  # (indirect) 工厂方法名

    @staticmethod
    def unknown():
        return RegState(kind="unknown")

    @staticmethod
    def module_ref(module: str):
        return RegState(kind="module_ref", module=module)

    @staticmethod
    def property_access(module: str, method: str):
        return RegState(kind="property_access", module=module, method=method)

    @staticmethod
    def call_result(module: str, method: str):
        return RegState(kind="call_result", module=module, method=method)

    @staticmethod
    def closure():
        return RegState(kind="closure")


class RegisterTracker:
    """追踪函数内寄存器和ACC的状态"""

    def __init__(self):
        self.acc: RegState = RegState.unknown()
        self.regs: dict[str, RegState] = {}

    def set_acc(self, state: RegState):
        self.acc = state

    def sta(self, reg: str):
        """sta vN: 将 ACC 值存入寄存器"""
        self.regs[reg] = RegState(
            kind=self.acc.kind,
            module=self.acc.module,
            method=self.acc.method,
            factory_module=self.acc.factory_module,
            factory_method=self.acc.factory_method,
        )

    def lda(self, reg: str):
        """lda vN: 将寄存器值加载到 ACC"""
        if reg in self.regs:
            src = self.regs[reg]
            self.acc = RegState(
                kind=src.kind,
                module=src.module,
                method=src.method,
                factory_module=src.factory_module,
                factory_method=src.factory_method,
            )
        else:
            self.acc = RegState.unknown()

    def get_reg(self, reg: str) -> RegState:
        return self.regs.get(reg, RegState.unknown())

    def to_state(self) -> BlockState:
        """序列化当前 tracker 状态为 BlockState (用于固定点迭代)"""
        return BlockState(
            acc_kind=self.acc.kind,
            acc_module=self.acc.module,
            acc_method=self.acc.method,
            acc_factory_module=self.acc.factory_module,
            acc_factory_method=self.acc.factory_method,
            regs={k: _reg_to_tuple(v) for k, v in self.regs.items()},
        )

    @classmethod
    def from_state(cls, state: BlockState) -> 'RegisterTracker':
        """从 BlockState 恢复 tracker 状态"""
        tracker = cls()
        tracker.acc = RegState(
            kind=state.acc_kind,
            module=state.acc_module,
            method=state.acc_method,
            factory_module=state.acc_factory_module,
            factory_method=state.acc_factory_method,
        )
        tracker.regs = {
            k: RegState(kind=v[0], module=v[1], method=v[2],
                        factory_module=v[3], factory_method=v[4])
            for k, v in state.regs.items()
        }
        return tracker


# ============================================================
# 规则加载
# ============================================================

@dataclass
class ApiRule:
    """一条API检测规则"""
    id: str
    module: str
    method: str
    paradigm: str
    category: str
    description: str


def load_rules(rules_path: str) -> list[ApiRule]:
    """加载 YAML 规则文件"""
    with open(rules_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    rules = []
    for r in data.get('rules', []):
        rules.append(ApiRule(
            id=r['id'],
            module=r['module'],
            method=r['method'],
            paradigm=r['paradigm'],
            category=r['category'],
            description=r['description'],
        ))
    return rules


class RuleMatcher:
    """规则快速匹配器"""

    def __init__(self, rules: list[ApiRule]):
        self.rules = rules
        # 构建 (module, method) -> [ApiRule] 索引
        self._index: dict[tuple[str, str], list[ApiRule]] = {}
        # 构建 module -> [ApiRule] 索引 (用于模块级匹配)
        self._module_index: dict[str, list[ApiRule]] = {}
        for rule in rules:
            key = (rule.module, rule.method)
            self._index.setdefault(key, []).append(rule)
            self._module_index.setdefault(rule.module, []).append(rule)

    def match(self, module: str, method: str) -> list[ApiRule]:
        """精确匹配 (module, method)"""
        return self._index.get((module, method), [])

    def is_sensitive_module(self, module: str) -> bool:
        """检查模块是否在规则库中"""
        return module in self._module_index

    def get_module_rules(self, module: str) -> list[ApiRule]:
        return self._module_index.get(module, [])


# ============================================================
# 核心检测引擎
# ============================================================

# Promise链方法和通用非隐私方法 (不应归因于模块)
# 这些方法出现在 call_result 上时，是对返回值的操作而非对模块的调用
_IGNORED_METHODS = {
    # Promise 链方法
    'then', 'catch', 'finally',
    # 通用日志/错误方法 (经常被错误归因)
    'log', 'error', 'info', 'warn', 'debug',
    # 资源清理方法 (非数据采集)
    'off', 'unsubscribe', 'close', 'release', 'destroy',
}

# 操作数解析辅助函数
RE_QUOTED_STRING = re.compile(r'"([^"]*)"')
RE_REGISTER = re.compile(r'v(\d+)')
RE_CALLTHIS = re.compile(r'^callthis(\d*)\s')


def _extract_string_operand(operands: str) -> str:
    """从操作数中提取引号内的字符串"""
    m = RE_QUOTED_STRING.search(operands)
    return m.group(1) if m else ""


def _extract_registers_from_callthis(operands: str) -> list[str]:
    """
    从 callthis 操作数中提取寄存器列表。
    格式: callthisN imm, vObj, [vArg1, vArg2, ...]
    返回: [vObj, vArg1, vArg2, ...]
    """
    parts = [p.strip() for p in operands.split(',')]
    regs = []
    for p in parts:
        if p.startswith('v') and p[1:].isdigit():
            regs.append(p)
    return regs


class ApiDetector:
    """
    隐私API检测引擎 (CFG-based)。

    对每个函数执行:
      1. 建立导入映射 (local_name -> module_request)
      2. 构建控制流图 (CFG)
      3. 固定点迭代: 传播寄存器状态至收敛
      4. 检测遍历: 在可达块中匹配规则
    """

    def __init__(self, pa: PaFile, resolver: ModuleResolver, matcher: RuleMatcher):
        self.pa = pa
        self.resolver = resolver
        self.matcher = matcher
        self.detections: list[ApiDetection] = []
        self.unmatched: list[UnmatchedApiCall] = []
        # 函数级临时状态 (在 _analyze_function 中设置)
        self._current_import_map = None
        self._current_func = None

    def analyze_all(self) -> list[ApiDetection]:
        """分析所有函数"""
        for func in self.pa.functions:
            self._analyze_function(func)
        return self.detections

    # ================================================================
    # CFG-based 两阶段分析
    # ================================================================

    def _analyze_function(self, func: PaFunction):
        """
        基于控制流图的函数分析 (两阶段)。

        Phase 1: 固定点迭代 — 在 RPO 顺序下传播寄存器状态至收敛
        Phase 2: 检测遍历 — 基于收敛状态，在可达块中生成检测结果
        """
        import_map = self.resolver.get_import_map(func)
        if not import_map:
            return

        # 检查该函数所在模块是否导入了任何敏感模块
        has_sensitive = any(
            self.matcher.is_sensitive_module(mod)
            for mod in import_map.values()
        )
        if not has_sensitive:
            return

        instructions = func.instructions
        if not instructions:
            return

        # 设置函数级上下文
        self._current_import_map = import_map
        self._current_func = func

        # ---- 构建控制流图 ----
        cfg = ControlFlowGraph.build(instructions, func.labels)
        reachable = cfg.reachable_blocks()
        rpo = cfg.reverse_postorder()

        # ---- Phase 1: 固定点迭代 (不生成检测) ----
        block_output = {}  # block_id -> BlockState

        changed = True
        while changed:
            changed = False
            for bid in rpo:
                if bid not in reachable:
                    continue
                block = cfg.blocks[bid]

                # 计算输入状态
                input_state = self._compute_block_input(block, block_output)

                # 处理块内指令 (仅状态转换)
                tracker = RegisterTracker.from_state(input_state)
                for idx in range(block.start_idx, block.end_idx):
                    self._step_instruction(tracker, instructions, idx,
                                           detect=False)

                # 检查输出状态是否收敛
                new_output = tracker.to_state()
                if bid not in block_output or new_output != block_output[bid]:
                    block_output[bid] = new_output
                    changed = True

        # ---- Phase 2: 检测遍历 (使用收敛状态) ----
        for bid in rpo:
            if bid not in reachable:
                continue
            block = cfg.blocks[bid]

            input_state = self._compute_block_input(block, block_output)
            tracker = RegisterTracker.from_state(input_state)

            for idx in range(block.start_idx, block.end_idx):
                self._step_instruction(tracker, instructions, idx,
                                       detect=True)

        # 清理函数级上下文
        self._current_import_map = None
        self._current_func = None

    def _compute_block_input(self, block, block_output) -> BlockState:
        """计算基本块的输入状态 (合并前驱块输出)"""
        if not block.predecessors:
            # 入口块或孤立块
            return BlockState()
        pred_states = [block_output[p] for p in block.predecessors
                       if p in block_output]
        if not pred_states:
            return BlockState()
        merged = merge_states(pred_states)
        if block.is_handler:
            # 异常处理入口: ACC 被异常对象覆盖, 但寄存器保留
            # PA VM 在异常路径中保留所有寄存器值
            merged.acc_kind = "unknown"
            merged.acc_module = ""
            merged.acc_method = ""
            merged.acc_factory_module = ""
            merged.acc_factory_method = ""
        return merged

    # ================================================================
    # 指令处理
    # ================================================================

    def _step_instruction(self, tracker, instructions, idx, detect=False):
        """
        处理单条指令的寄存器状态转换。
        当 detect=True 时，同时生成检测结果。

        分支/终止指令由 CFG 处理，此处仅做状态标记或跳过。
        """
        inst = instructions[idx]
        op = inst.opcode
        func = self._current_func
        import_map = self._current_import_map

        # ---- 分支/终止指令: CFG 已处理控制流, 此处无需状态转换 ----
        if op in ('return', 'returnundefined', 'throw',
                  'jmp', 'jeqz', 'jnez',
                  'jstricteqz', 'jstrictnoteqz', 'jequndefined'):
            return

        # ------- ldexternalmodulevar -------
        if op == 'ldexternalmodulevar':
            local_name = self._peek_local_name(instructions, idx)
            if local_name:
                module_req = import_map.get(local_name, "")
                if module_req:
                    tracker.set_acc(RegState.module_ref(module_req))
                else:
                    tracker.set_acc(RegState.unknown())
            else:
                tracker.set_acc(RegState.unknown())

        # ------- throw.undefinedifholewithname -------
        elif op == 'throw.undefinedifholewithname':
            # ACC 状态已在 ldexternalmodulevar 中设置, 跳过
            pass

        # ------- sta vN -------
        elif op == 'sta':
            reg = inst.operands.strip()
            if reg.startswith('v'):
                tracker.sta(reg)

        # ------- lda vN -------
        elif op == 'lda':
            reg = inst.operands.strip()
            if reg.startswith('v'):
                tracker.lda(reg)

        # ------- ldobjbyname imm, "methodName" -------
        elif op == 'ldobjbyname':
            prop_name = _extract_string_operand(inst.operands)
            if not prop_name:
                tracker.set_acc(RegState.unknown())
                return

            acc = tracker.acc
            if acc.kind == 'module_ref':
                # 在模块上访问属性/方法
                tracker.set_acc(RegState.property_access(acc.module, prop_name))

                # 检查范式4: constant_access (仅在检测阶段)
                if detect:
                    next_op = self._peek_next_effective_opcode(instructions, idx)
                    if next_op and not next_op.startswith('call'):
                        rules = self.matcher.match(acc.module, prop_name)
                        for rule in rules:
                            if rule.paradigm == 'constant_access':
                                ctx = self._extract_data_sink(instructions, idx)
                                if not ctx:
                                    ctx = self._extract_page_context(func.name)
                                self.detections.append(ApiDetection(
                                    rule_id=rule.id,
                                    module=acc.module,
                                    method=prop_name,
                                    paradigm='constant_access',
                                    category=rule.category,
                                    description=rule.description,
                                    function_name=func.name,
                                    line_no=inst.line_no,
                                    context=ctx,
                                ))

            elif acc.kind == 'call_result':
                # 在调用结果上访问属性 (可能是间接调用链的下一步)
                if prop_name in _IGNORED_METHODS:
                    tracker.set_acc(RegState.unknown())
                else:
                    tracker.set_acc(RegState(
                        kind='property_access',
                        module=acc.module,
                        method=prop_name,
                        factory_module=acc.module,
                        factory_method=acc.method,
                    ))
            elif acc.kind == 'property_access':
                # 链式属性访问 e.g. sensor.SensorId -> sensor.SensorId.ACCELEROMETER
                tracker.set_acc(RegState.property_access(acc.module, prop_name))
            else:
                tracker.set_acc(RegState.unknown())

        # ------- callthis0/1/2/3/... / callarg / wide.callthis -------
        elif (op.startswith('callthis') or op.startswith('callarg')
              or op.startswith('wide.callthis')):
            self._handle_call(tracker, inst, instructions, idx, detect=detect)

        # ------- definefunc -------
        elif op == 'definefunc':
            tracker.set_acc(RegState.closure())

        # ------- mov vN, vM -------
        elif op == 'mov':
            parts = [p.strip() for p in inst.operands.split(',')]
            if len(parts) == 2:
                dst, src = parts[0], parts[1]
                if src.startswith('v') and src[1:].isdigit():
                    src_state = tracker.get_reg(src)
                    tracker.regs[dst] = RegState(
                        kind=src_state.kind, module=src_state.module,
                        method=src_state.method,
                        factory_module=src_state.factory_module,
                        factory_method=src_state.factory_method,
                    )

        # ------- lda.str: 字符串常量追踪 -------
        elif op == 'lda.str':
            str_val = _extract_string_operand(inst.operands)
            if str_val:
                tracker.set_acc(RegState(kind='string_const', method=str_val))
            else:
                tracker.set_acc(RegState.unknown())

        # ------- ldai / ldundefined / ldnull / ldtrue / ldfalse -------
        elif op in ('ldai', 'fldai', 'ldundefined', 'ldnull',
                    'ldtrue', 'ldfalse', 'ldhole'):
            tracker.set_acc(RegState.unknown())

        # ------- 其他指令: 使ACC进入 unknown 状态 -------
        elif op in ('createemptyarray', 'createarraywithbuffer',
                    'createobjectwithbuffer', 'newobjrange',
                    'newlexenv', 'newlexenvwithname',
                    'asyncfunctionenter', 'typeof',
                    'instanceof', 'isin', 'neg', 'inc', 'dec',
                    'not', 'add2', 'sub2', 'mul2', 'div2', 'mod2',
                    'eq', 'noteq', 'stricteq', 'strictnoteq',
                    'less', 'lesseq', 'greater', 'greatereq',
                    'tonumeric', 'tonumber', 'getiterator',
                    'getnextpropname', 'getresumemode',
                    'resumegenerator', 'suspendgenerator',
                    'asyncfunctionawaituncaught', 'asyncfunctionresolve',
                    'asyncfunctionreject', 'poplexenv',
                    'defineclasswithbuffer'):
            tracker.set_acc(RegState.unknown())

    # ================================================================
    # 调用处理
    # ================================================================

    def _handle_call(self, tracker, inst, instructions, idx, detect=True):
        """处理 callthis/callarg 指令"""
        acc = tracker.acc
        regs = _extract_registers_from_callthis(inst.operands)
        func = self._current_func

        if acc.kind == 'property_access':
            module = acc.module
            method = acc.method

            # 确定范式类型
            paradigm = "direct_invoke"
            context = ""

            # 检查是否有回调参数 (范式3)
            has_closure_arg = False
            for reg in regs[1:]:  # 跳过第一个 (this)
                reg_state = tracker.get_reg(reg)
                if reg_state.kind == 'closure':
                    has_closure_arg = True
                    break

            if has_closure_arg:
                paradigm = "callback_invoke"
                # 提取回调事件类型 (如 SensorId.ACCELEROMETER)
                context = self._extract_callback_event(tracker, regs)

            # 检查是否为间接调用链 (范式1)
            if acc.factory_method:
                paradigm = "indirect_invoke"
                context = f"via {acc.factory_method}()"

            # 对于 direct_invoke，追踪数据去向
            if not context:
                context = self._extract_data_sink(instructions, idx)

            # 兜底: 从函数名提取页面信息
            if not context:
                context = self._extract_page_context(func.name)

            # 匹配规则 (仅在检测阶段)
            if detect:
                rules = self.matcher.match(module, method)
                if rules:
                    for rule in rules:
                        self.detections.append(ApiDetection(
                            rule_id=rule.id,
                            module=module,
                            method=method,
                            paradigm=paradigm,
                            category=rule.category,
                            description=rule.description,
                            function_name=func.name,
                            line_no=inst.line_no,
                            context=context,
                        ))
                else:
                    # 如果模块是敏感模块但方法不在规则中, 记录为 unmatched
                    if self.matcher.is_sensitive_module(module) and method not in _IGNORED_METHODS:
                        self.unmatched.append(UnmatchedApiCall(
                            module=module,
                            method=method,
                            function_name=func.name,
                            line_no=inst.line_no,
                        ))

            # 设置 ACC 为调用结果 (始终更新状态)
            tracker.set_acc(RegState.call_result(module, method))
        else:
            # 非模块方法调用
            tracker.set_acc(RegState.unknown())

    # ================================================================
    # 辅助方法
    # ================================================================

    def _peek_local_name(self, instructions: list[Instruction], current_idx: int) -> str:
        """向前查看下一条 throw.undefinedifholewithname 指令以获取 local_name"""
        for i in range(current_idx + 1, min(current_idx + 3, len(instructions))):
            inst = instructions[i]
            if inst.opcode == 'throw.undefinedifholewithname':
                return _extract_string_operand(inst.operands)
        return ""

    def _peek_next_effective_opcode(self, instructions: list[Instruction], current_idx: int) -> str:
        """
        向前查看下一条有效指令的操作码。
        跳过 sta/lda 指令（因为它们只是数据移动）。
        """
        for i in range(current_idx + 1, min(current_idx + 5, len(instructions))):
            inst = instructions[i]
            if inst.opcode not in ('sta', 'lda', 'throw.undefinedifholewithname'):
                return inst.opcode
        return ""

    def _extract_data_sink(self, instructions: list[Instruction], current_idx: int) -> str:
        """
        向后查看 ~20 条指令，追踪 ACC(调用结果/常量值) 的数据去向。
        返回描述性 context 字符串, 如 "stored to .wifiInfo" 或 "returned"。
        自动跳过 async/generator 噪音指令。
        """
        stored_reg = None  # 记录结果被存入的寄存器

        # async/generator 噪音指令 — 跳过, 不中断追踪
        _ASYNC_NOISE = frozenset((
            'asyncfunctionawaituncaught', 'suspendgenerator',
            'resumegenerator', 'getresumemode',
            'throw.undefinedifholewithname',
            'asyncfunctionresolve', 'asyncfunctionreject',
        ))

        for i in range(current_idx + 1, min(current_idx + 20, len(instructions))):
            inst = instructions[i]

            # 跳过 async/generator 噪音
            if inst.opcode in _ASYNC_NOISE:
                continue

            # 跳过简单数据移动 (lda vN)
            if inst.opcode == 'lda':
                continue

            # 结果被存入寄存器 vN
            if inst.opcode == 'sta' and stored_reg is None:
                stored_reg = inst.operands.strip()
                continue

            # 结果被赋值到对象属性
            if inst.opcode in ('stobjbyname', 'stownbyname'):
                prop = _extract_string_operand(inst.operands)
                if prop:
                    return f"stored to .{prop}"

            # 结果被链式调用 (在 ACC 或 stored_reg 上继续操作)
            if inst.opcode == 'ldobjbyname':
                prop = _extract_string_operand(inst.operands)
                if prop:
                    return f"result -> .{prop}()"

            # 结果被返回
            if inst.opcode in ('return', 'returnundefined'):
                return "returned"

            # 遇到新的模块加载或非相关调用, 停止追踪
            if inst.opcode in ('ldexternalmodulevar', 'definefunc',
                               'createobjectwithbuffer', 'createemptyarray'):
                break

            # 遇到另一个 callthis (非链式), 停止
            if inst.opcode.startswith('callthis') or inst.opcode.startswith('callarg'):
                break

            # 遇到跳转, 停止 (不跨越基本块)
            if inst.opcode in ('jmp', 'jeqz', 'jnez', 'jstricteqz', 'jstrictnoteqz'):
                break

        return ""

    def _extract_callback_event(self, tracker: RegisterTracker, regs: list[str]) -> str:
        """
        从回调调用的参数中提取事件类型。
        例如: sensor.on(sensor.SensorId.ACCELEROMETER, callback)
        参数寄存器中若有 property_access / string_const 状态, 提取作为事件类型。
        """
        for reg in regs[1:]:  # 跳过第一个 (this)
            state = tracker.get_reg(reg)
            if state.kind == 'property_access':
                # 模块属性访问 (如 sensor.SensorId.ACCELEROMETER)
                return f"listener: {state.method}"
            elif state.kind == 'string_const':
                # 字符串常量参数 (如 "accelerometer")
                return f'listener: "{state.method}"'
            elif state.kind == 'closure':
                continue  # 跳过回调函数本身
        return ""

    def _extract_page_context(self, func_name: str) -> str:
        """
        从函数完全限定名中提取页面信息作为兜底 context。
        例如: com.xxx.pages.sensor.sensor → "in page: sensor"
        """
        parts = func_name.split('.')
        for i, p in enumerate(parts):
            if p == 'pages' and i + 1 < len(parts):
                return f"in page: {parts[i + 1]}"
        return ""


# ============================================================
# 调试入口
# ============================================================
if __name__ == "__main__":
    import sys
    from pa_parser import parse_pa_file

    if len(sys.argv) < 2:
        print("Usage: python api_detector.py <file.pa>")
        sys.exit(1)

    rules_path = str(Path(__file__).parent / "rules" / "privacy_api_rules.yaml")
    pa = parse_pa_file(sys.argv[1])
    resolver = ModuleResolver(pa)
    rules = load_rules(rules_path)
    matcher = RuleMatcher(rules)
    detector = ApiDetector(pa, resolver, matcher)
    results = detector.analyze_all()

    print(f"\n[RESULT] Total detections: {len(results)}")
    for d in results:
        ctx = f" | {d.context}" if d.context else ""
        print(f"  [{d.paradigm}] {d.module}.{d.method} "
              f"in {d.function_name} @ line {d.line_no} "
              f"(category={d.category}{ctx})")
