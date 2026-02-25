"""
函数间调用图构建模块 (callgraph.py)
=====================================
从 PaFile 中提取函数间的调用关系，构建全局调用图 (Call Graph)。

支持的调用边类型:
  - definefunc 引用: 函数内通过 definefunc 创建另一个函数的闭包引用
  - callarg 调用: 通过 callarg0/1/args2/args3 直接调用寄存器中的函数
  - callthis 调用: 通过 callthis0/1/2/3/range 在对象上调用方法  
  - newobjrange 构造: 通过 new 调用构造函数
  - 外部模块 API 调用: ldexternalmodulevar + ldobjbyname + callthis 链

调用图节点:
  - 每个 .function 定义对应一个节点
  - 外部模块 API 调用记录为虚拟节点 (module::method)
"""

from dataclasses import dataclass, field
from .parser import PaFile, PaFunction


# ============================================================
# 调用边类型
# ============================================================

EDGE_DEFINEFUNC = "definefunc"       # 函数闭包引用 (已解析目标)
EDGE_CALLARG = "callarg"             # 直接函数调用
EDGE_CALLTHIS = "callthis"           # 方法调用 (对象上)
EDGE_NEWOBJRANGE = "newobjrange"     # 构造函数调用
EDGE_EXTERNAL_API = "external_api"   # 外部模块 API 调用
EDGE_IMPLICIT_UI = "implicit_ui"     # ArkUI 声明式框架隐式调用 (虚拟边)


# ============================================================
# 数据结构
# ============================================================

@dataclass
class CallEdge:
    """一条调用边"""
    caller: str            # 调用者函数全限定名
    callee: str            # 被调用函数全限定名 (或外部 API 如 "@ohos:pasteboard::getData")
    edge_type: str         # EDGE_* 常量
    line_no: int = 0       # 调用指令在 .pa 文件中的行号
    call_info: str = ""    # 额外信息 (如方法名、模块名)


@dataclass
class CallGraphNode:
    """调用图中的一个节点"""
    name: str                                        # 函数全限定名
    is_external: bool = False                        # 是否为外部 API 虚拟节点
    outgoing: list = field(default_factory=list)      # [CallEdge, ...] 出边 (本函数调用了谁)
    incoming: list = field(default_factory=list)      # [CallEdge, ...] 入边 (谁调用了本函数)


class CallGraph:
    """
    全局函数调用图。

    节点为函数定义，边为调用关系。
    支持查询调用者/被调用者、计算入度/出度、
    识别根节点和叶节点等图操作。
    """

    def __init__(self):
        self.nodes: dict[str, CallGraphNode] = {}    # name -> CallGraphNode
        self.edges: list[CallEdge] = []

    def _ensure_node(self, name: str, is_external: bool = False) -> CallGraphNode:
        """确保节点存在，不存在则创建"""
        if name not in self.nodes:
            self.nodes[name] = CallGraphNode(name=name, is_external=is_external)
        return self.nodes[name]

    def add_edge(self, edge: CallEdge):
        """添加一条调用边"""
        caller_node = self._ensure_node(edge.caller)
        callee_node = self._ensure_node(
            edge.callee,
            is_external=(edge.edge_type == EDGE_EXTERNAL_API)
        )
        caller_node.outgoing.append(edge)
        callee_node.incoming.append(edge)
        self.edges.append(edge)

    # ---- 查询接口 ----

    def callees_of(self, func_name: str) -> list[str]:
        """获取函数直接调用的所有被调用者"""
        node = self.nodes.get(func_name)
        if not node:
            return []
        return list({e.callee for e in node.outgoing})

    def callers_of(self, func_name: str) -> list[str]:
        """获取函数的所有直接调用者"""
        node = self.nodes.get(func_name)
        if not node:
            return []
        return list({e.caller for e in node.incoming})

    def roots(self) -> list[str]:
        """返回入度为 0 的根节点 (无人调用的函数)"""
        return [name for name, node in self.nodes.items()
                if not node.incoming and not node.is_external]

    def leaves(self) -> list[str]:
        """返回出度为 0 的叶节点 (不调用其他函数的函数)"""
        return [name for name, node in self.nodes.items()
                if not node.outgoing and not node.is_external]

    def internal_nodes(self) -> list[str]:
        """返回所有内部函数节点 (非外部 API)"""
        return [name for name, node in self.nodes.items()
                if not node.is_external]

    def external_nodes(self) -> list[str]:
        """返回所有外部 API 虚拟节点"""
        return [name for name, node in self.nodes.items()
                if node.is_external]

    def stats(self) -> dict:
        """返回调用图统计信息"""
        internal = [n for n in self.nodes.values() if not n.is_external]
        external = [n for n in self.nodes.values() if n.is_external]
        return {
            'total_nodes': len(self.nodes),
            'internal_functions': len(internal),
            'external_apis': len(external),
            'total_edges': len(self.edges),
            'edge_types': _count_edge_types(self.edges),
            'root_functions': len(self.roots()),
            'leaf_functions': len(self.leaves()),
        }


def _count_edge_types(edges: list[CallEdge]) -> dict:
    """按类型统计边数"""
    counts = {}
    for e in edges:
        counts[e.edge_type] = counts.get(e.edge_type, 0) + 1
    return counts


# ============================================================
# 调用图构建
# ============================================================

# definefunc 目标中的函数名提取:
# 格式: "com.xxx.funcName.#hash#(any,any,...)"
# 策略: 截取 '(' 之前的部分作为函数全限定名

# callarg/callthis 调用的目标解析:
# 需要通过寄存器状态追踪 definefunc 的结果来确定目标
# 这里采用轻量级的局部向前查找策略


def build_call_graph(pa: PaFile, import_resolver=None) -> CallGraph:
    """
    从 PaFile 构建全局调用图。

    Args:
        pa: 解析后的 PA 文件
        import_resolver: 可选的 ModuleResolver，用于解析外部模块调用

    Returns:
        CallGraph 实例
    """
    cg = CallGraph()

    # 建立函数名索引 (用于 definefunc 目标匹配)
    func_name_set = {f.name for f in pa.functions}

    # 为每个 .function 定义创建节点
    for func in pa.functions:
        cg._ensure_node(func.name)

    # 分析每个函数内部的调用指令
    for func in pa.functions:
        _analyze_function_calls(cg, func, func_name_set, pa, import_resolver)

    return cg


def _extract_definefunc_target(operands: str, func_name_set: set) -> str | None:
    """
    从 definefunc 操作数中提取目标函数名。

    operands 格式: "0x1b, com.xxx.funcName.#hash#(any,any,...)"
    返回匹配到的函数全限定名，或 None。
    """
    parts = operands.split(',', 1)
    if len(parts) < 2:
        return None

    raw_target = parts[1].strip()

    # 截取 '(' 之前的部分
    paren_idx = raw_target.find('(')
    if paren_idx > 0:
        name_part = raw_target[:paren_idx]
    else:
        name_part = raw_target

    # 精确匹配
    if name_part in func_name_set:
        return name_part

    # 尝试最长前缀匹配 (definefunc 目标可能包含 .#hash# 后缀)
    best_match = None
    best_len = 0
    for fname in func_name_set:
        if name_part.startswith(fname) and len(fname) > best_len:
            best_match = fname
            best_len = len(fname)

    return best_match


def _analyze_function_calls(cg: CallGraph, func: PaFunction,
                            func_name_set: set, pa: PaFile,
                            import_resolver) -> None:
    """分析单个函数内部的所有调用指令，提取调用边。"""
    instructions = func.instructions

    # 轻量级寄存器追踪: 记录每个寄存器持有的函数引用
    # reg -> (type, value)
    #   type="func_ref": value=函数名  (来自 definefunc)
    #   type="module_ref": value=模块路径  (来自 ldexternalmodulevar)
    #   type="method_ref": value=(模块路径, 方法名)  (来自 ldobjbyname)
    reg_state = {}
    acc_state = (None, None)  # (type, value)

    # 获取模块导入映射 (如果有 resolver)
    import_map = {}
    if import_resolver:
        import_map = import_resolver.get_import_map(func)

    # 构建 ldexternalmodulevar 索引 -> 模块名 的映射
    module_idx_map = {}
    if import_map:
        for local_name, module_path in import_map.items():
            # 需要从 REGULAR_IMPORT 中找到对应的 module_request_idx
            # 这里简化处理：按照 import_map 的顺序对应索引
            pass

    # 更精确的方式: 通过 resolver 获取完整的导入表信息
    idx_to_module = {}
    if import_resolver:
        rec = import_resolver.resolve_function_record(func)
        if rec and rec.module_record_idx:
            lit = pa.hex_to_literal.get(rec.module_record_idx)
            if lit:
                # 建立 REGULAR_IMPORT 的索引顺序映射
                for i, imp in enumerate(lit.regular_imports):
                    idx_to_module[i] = imp.module_request

    for inst in instructions:
        op = inst.opcode
        operands = inst.operands

        if op == 'definefunc':
            # definefunc 创建函数闭包引用
            target = _extract_definefunc_target(operands, func_name_set)
            if target:
                # ACC 持有闭包引用
                acc_state = ("func_ref", target)
                # 添加 definefunc 引用边
                cg.add_edge(CallEdge(
                    caller=func.name,
                    callee=target,
                    edge_type=EDGE_DEFINEFUNC,
                    line_no=inst.line_no,
                    call_info="definefunc"
                ))
            else:
                acc_state = (None, None)

        elif op == 'ldexternalmodulevar':
            # 加载外部模块引用到 ACC
            try:
                idx_str = operands.strip()
                idx = int(idx_str, 16) if idx_str.startswith('0x') else int(idx_str)
                module_path = idx_to_module.get(idx, f"?module_{idx}")
                acc_state = ("module_ref", module_path)
            except (ValueError, IndexError):
                acc_state = (None, None)

        elif op == 'ldobjbyname':
            # 在对象上按名读取属性/方法
            parts = operands.split(',', 1)
            if len(parts) >= 2:
                method_name = parts[1].strip().strip('"')
                if acc_state[0] == "module_ref":
                    # 记录属性/方法引用
                    acc_state = ("method_ref", (acc_state[1], method_name))
                    # constant_access 范式: 直接读取模块常量属性
                    # 如 @ohos:deviceInfo 的 brand, serial 等
                    # 生成一条 external_api 边（属性读取也是一种访问）
                    callee_name = f"{acc_state[1][0]}::{method_name}"
                    cg.add_edge(CallEdge(
                        caller=func.name,
                        callee=callee_name,
                        edge_type=EDGE_EXTERNAL_API,
                        line_no=inst.line_no,
                        call_info=f"{acc_state[1][0]}.{method_name} (property_access)"
                    ))
                elif acc_state[0] == "factory_instance":
                    acc_state = ("method_ref", (acc_state[1], method_name))
                else:
                    acc_state = ("method_ref", ("?", method_name))

        elif op == 'sta':
            # 将 ACC 存入寄存器
            reg_name = operands.strip()
            if acc_state[0] is not None:
                reg_state[reg_name] = acc_state

        elif op == 'lda':
            # 从寄存器加载到 ACC
            reg_name = operands.strip()
            acc_state = reg_state.get(reg_name, (None, None))

        elif op == 'mov':
            # 寄存器间复制
            parts = operands.split(',')
            if len(parts) >= 2:
                dst = parts[0].strip()
                src = parts[1].strip()
                reg_state[dst] = reg_state.get(src, (None, None))

        elif op in ('callarg0', 'callarg1', 'callargs2', 'callargs3',
                    'callrange', 'wide.callrange'):
            # 直接函数调用: callarg0 0x0, vN  (vN 持有函数引用)
            parts = operands.split(',')
            if len(parts) >= 2:
                target_reg = parts[1].strip()
                state = reg_state.get(target_reg, (None, None))
                if state[0] == "func_ref":
                    cg.add_edge(CallEdge(
                        caller=func.name,
                        callee=state[1],
                        edge_type=EDGE_CALLARG,
                        line_no=inst.line_no,
                        call_info=f"callarg -> {state[1]}"
                    ))
                elif state[0] == "method_ref" and isinstance(state[1], tuple):
                    # ACC 中的方法引用被 sta 到 vN 后通过 callarg 调用
                    module_path, method_name = state[1]
                    if module_path != "?":
                        callee_name = f"{module_path}::{method_name}"
                        cg.add_edge(CallEdge(
                            caller=func.name,
                            callee=callee_name,
                            edge_type=EDGE_EXTERNAL_API,
                            line_no=inst.line_no,
                            call_info=f"{module_path}.{method_name} (callarg)"
                        ))
            # 同时检查 ACC: 某些调用模式函数引用在 ACC 中
            if acc_state[0] == "method_ref" and isinstance(acc_state[1], tuple):
                module_path, method_name = acc_state[1]
                if module_path != "?":
                    callee_name = f"{module_path}::{method_name}"
                    cg.add_edge(CallEdge(
                        caller=func.name,
                        callee=callee_name,
                        edge_type=EDGE_EXTERNAL_API,
                        line_no=inst.line_no,
                        call_info=f"{module_path}.{method_name} (callarg-acc)"
                    ))
            elif acc_state[0] == "func_ref" and acc_state[1]:
                cg.add_edge(CallEdge(
                    caller=func.name,
                    callee=acc_state[1],
                    edge_type=EDGE_CALLARG,
                    line_no=inst.line_no,
                    call_info=f"callarg-acc -> {acc_state[1]}"
                ))
            # ACC = 调用返回值
            acc_state = (None, None)

        elif op in ('callthis0', 'callthis1', 'callthis2', 'callthis3', 'callthisrange'):
            # 方法调用: callthis0 0x0, vN  (vN 持有 this 对象)
            parts = operands.split(',')
            if len(parts) >= 2:
                this_reg = parts[1].strip()
                this_state = reg_state.get(this_reg, (None, None))

                if this_state[0] == "module_ref":
                    # 直接在模块上调用: module.method()
                    # ACC 应该持有 method_ref
                    if acc_state[0] == "method_ref" and isinstance(acc_state[1], tuple):
                        module_path, method_name = acc_state[1]
                        callee_name = f"{module_path}::{method_name}"
                        cg.add_edge(CallEdge(
                            caller=func.name,
                            callee=callee_name,
                            edge_type=EDGE_EXTERNAL_API,
                            line_no=inst.line_no,
                            call_info=f"{module_path}.{method_name}"
                        ))
                        # 调用结果可能是工厂实例
                        acc_state = ("factory_instance", module_path)

                elif this_state[0] == "factory_instance":
                    # 在工厂实例上调用: instance.method()
                    if acc_state[0] == "method_ref" and isinstance(acc_state[1], tuple):
                        module_path, method_name = acc_state[1]
                        callee_name = f"{this_state[1]}::{method_name}"
                        cg.add_edge(CallEdge(
                            caller=func.name,
                            callee=callee_name,
                            edge_type=EDGE_EXTERNAL_API,
                            line_no=inst.line_no,
                            call_info=f"{this_state[1]}.{method_name}"
                        ))
                    acc_state = (None, None)

                elif this_state[0] == "func_ref":
                    # 调用内部函数
                    cg.add_edge(CallEdge(
                        caller=func.name,
                        callee=this_state[1],
                        edge_type=EDGE_CALLTHIS,
                        line_no=inst.line_no,
                    ))
                    acc_state = (None, None)

                else:
                    # this 对象未知，尝试从 ACC 提取方法信息
                    if acc_state[0] == "method_ref" and isinstance(acc_state[1], tuple):
                        _, method_name = acc_state[1]
                        # 记录为未解析的方法调用
                        callee_name = f"?::{method_name}"
                        cg.add_edge(CallEdge(
                            caller=func.name,
                            callee=callee_name,
                            edge_type=EDGE_CALLTHIS,
                            line_no=inst.line_no,
                            call_info=f"unresolved.{method_name}"
                        ))
                    acc_state = (None, None)

        elif op == 'newobjrange':
            # 构造函数调用: newobjrange 0x0, 0xN, vR
            # vR 通常持有构造函数引用
            parts = operands.split(',')
            if len(parts) >= 3:
                ctor_reg = parts[2].strip()
                state = reg_state.get(ctor_reg, (None, None))
                if state[0] == "func_ref":
                    cg.add_edge(CallEdge(
                        caller=func.name,
                        callee=state[1],
                        edge_type=EDGE_NEWOBJRANGE,
                        line_no=inst.line_no,
                        call_info=f"new {state[1]}"
                    ))
            acc_state = (None, None)

        elif op == 'defineclasswithbuffer':
            # 类定义: defineclasswithbuffer 0x0, com.xxx.ClassName.#hash#(...)
            target = _extract_definefunc_target(operands, func_name_set)
            if target:
                acc_state = ("func_ref", target)
            else:
                acc_state = (None, None)

        elif op in ('add2', 'sub2', 'mul2', 'div2', 'neg', 'inc',
                     'eq', 'noteq', 'stricteq', 'strictnoteq',
                     'less', 'lesseq', 'greater', 'greatereq',
                     'istrue', 'isfalse', 'isin', 'ldai', 'fldai',
                     'ldtrue', 'ldfalse', 'ldnull', 'ldundefined', 'ldhole',
                     'return', 'returnundefined', 'throw',
                     'asyncfunctionenter', 'asyncfunctionresolve', 'asyncfunctionreject',
                     'suspendgenerator', 'resumegenerator', 'getresumemode'):
            # 这些指令重置 ACC 状态
            acc_state = (None, None)


# ============================================================
# 调试: 独立运行时打印统计信息
# ============================================================
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '..')

    if len(sys.argv) < 2:
        print("Usage: python -m pandora.core.callgraph <file.pa>")
        sys.exit(1)

    from .parser import parse_pa_file
    from .resolver import ModuleResolver

    pa = parse_pa_file(sys.argv[1])
    resolver = ModuleResolver(pa)
    cg = build_call_graph(pa, import_resolver=resolver)

    stats = cg.stats()
    print(f"[CALLGRAPH] Call Graph Statistics:")
    for key, val in stats.items():
        print(f"  {key}: {val}")

    # Show top callers
    print(f"\n[CALLGRAPH] Top 10 callers by outgoing edges:")
    sorted_nodes = sorted(
        [(n, node) for n, node in cg.nodes.items() if not node.is_external],
        key=lambda x: len(x[1].outgoing), reverse=True
    )
    for name, node in sorted_nodes[:10]:
        print(f"  {name}: {len(node.outgoing)} calls")
        for e in node.outgoing[:5]:
            print(f"    -> {e.callee} ({e.edge_type})")
