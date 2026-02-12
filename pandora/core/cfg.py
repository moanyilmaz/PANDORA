"""
控制流图模块 (cfg.py)
=====================
从PA字节码指令序列构建控制流图 (CFG)，提供:
  - 基本块划分与边构建
  - 可达性分析 (BFS)
  - 逆后序遍历 (Reverse Postorder)
  - 寄存器状态合并 (用于固定点迭代)
"""

from dataclasses import dataclass, field


# ============================================================
# 跳转指令分类
# ============================================================

# 无条件跳转 — 1条边 → 目标块
_UNCONDITIONAL_JUMPS = frozenset({'jmp'})

# 条件跳转 — 2条边 → 目标块 + 直落块
_CONDITIONAL_JUMPS = frozenset({
    'jeqz', 'jnez',
    'jstricteqz', 'jstrictnoteqz',
    'jequndefined',
})

_BRANCH_OPCODES = _UNCONDITIONAL_JUMPS | _CONDITIONAL_JUMPS

# 终止指令 — 0条边 (出口)
_TERMINATORS = frozenset({'return', 'returnundefined', 'throw'})


# ============================================================
# 数据结构
# ============================================================

@dataclass
class BasicBlock:
    """一个基本块: 线性执行的指令序列，只有一个入口和出口"""
    id: int
    start_idx: int              # 起始指令索引 (inclusive)
    end_idx: int                # 结束指令索引 (exclusive)
    successors: list = field(default_factory=list)    # [block_id, ...]
    predecessors: list = field(default_factory=list)  # [block_id, ...]
    is_handler: bool = False    # 是否为异常处理程序入口


@dataclass
class BlockState:
    """基本块边界处的寄存器状态快照，用于数据流分析"""
    acc_kind: str = "unknown"
    acc_module: str = ""
    acc_method: str = ""
    acc_factory_module: str = ""
    acc_factory_method: str = ""
    regs: dict = field(default_factory=dict)  # reg_name -> (kind, module, method, f_mod, f_meth)

    def __eq__(self, other):
        if not isinstance(other, BlockState):
            return False
        return (self.acc_kind == other.acc_kind and
                self.acc_module == other.acc_module and
                self.acc_method == other.acc_method and
                self.acc_factory_module == other.acc_factory_module and
                self.acc_factory_method == other.acc_factory_method and
                self.regs == other.regs)

    def __ne__(self, other):
        return not self.__eq__(other)


# ============================================================
# 控制流图
# ============================================================

class ControlFlowGraph:
    """
    控制流图 (CFG)。

    从指令序列和标签映射构建基本块，建立前驱/后继边，
    提供可达性分析和逆后序遍历。
    """

    def __init__(self, blocks: list, entry_id: int):
        self.blocks: list[BasicBlock] = blocks
        self.entry_id: int = entry_id

    @staticmethod
    def build(instructions, labels):
        """
        从指令列表和标签映射构建CFG。

        Args:
            instructions: 指令列表 [Instruction, ...]
            labels: 标签映射 {label_name: instruction_index}

        Returns:
            ControlFlowGraph 实例
        """
        n = len(instructions)
        if n == 0:
            return ControlFlowGraph([], 0)

        # ---- Step 1: 确定基本块边界 ----
        block_starts = {0}  # 函数入口

        # 标签目标 → 块起始
        for _label, idx in labels.items():
            if 0 <= idx < n:
                block_starts.add(idx)

        # 分支/终止指令 → 下一条为块起始 (直落边)
        for idx, inst in enumerate(instructions):
            if inst.opcode in _BRANCH_OPCODES or inst.opcode in _TERMINATORS:
                if idx + 1 < n:
                    block_starts.add(idx + 1)

        # ---- Step 2: 创建基本块 ----
        sorted_starts = sorted(block_starts)
        blocks = []
        start_to_bid = {}  # start_idx -> block_id

        for i, start in enumerate(sorted_starts):
            end = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else n
            block = BasicBlock(id=i, start_idx=start, end_idx=end)
            blocks.append(block)
            start_to_bid[start] = i

        # 标记异常处理块
        for label, idx in labels.items():
            if 'handler_begin' in label and idx in start_to_bid:
                blocks[start_to_bid[idx]].is_handler = True

        # ---- Step 3: 构建显式边 ----
        # 标签 → 块ID 映射
        label_to_bid = {}
        for label, idx in labels.items():
            if idx in start_to_bid:
                label_to_bid[label] = start_to_bid[idx]

        for block in blocks:
            if block.end_idx <= 0 or block.end_idx - 1 >= n:
                continue

            last_inst = instructions[block.end_idx - 1]
            op = last_inst.opcode

            if op in _UNCONDITIONAL_JUMPS:
                # 无条件跳转: 1条边 → 目标
                target = last_inst.operands.strip()
                if target in label_to_bid:
                    succ = label_to_bid[target]
                    block.successors.append(succ)
                    blocks[succ].predecessors.append(block.id)

            elif op in _CONDITIONAL_JUMPS:
                # 条件跳转: 2条边 → 目标 + 直落
                target = last_inst.operands.strip()
                if target in label_to_bid:
                    succ = label_to_bid[target]
                    block.successors.append(succ)
                    blocks[succ].predecessors.append(block.id)
                # 直落边
                if block.end_idx in start_to_bid:
                    ft = start_to_bid[block.end_idx]
                    block.successors.append(ft)
                    blocks[ft].predecessors.append(block.id)

            elif op in _TERMINATORS:
                pass  # 无后继 (函数出口)

            else:
                # 非分支/终止: 直落到下一个块
                if block.end_idx in start_to_bid:
                    ft = start_to_bid[block.end_idx]
                    block.successors.append(ft)
                    blocks[ft].predecessors.append(block.id)

        # ---- Step 4: 构建 try→handler 隐式边 ----
        # PA bytecode try-catch 结构:
        #   try_begin_label_N → try_end_label_N → handler_begin_label_N_M
        # try 区域内任何指令都可能抛异常跳转到 handler,
        # 因此 try 区域的入口块需要有边到 handler (保证寄存器状态传播)。
        import re
        try_regions = {}  # N -> {'begin': idx, 'end': idx, 'handlers': [idx, ...]}
        for label, idx in labels.items():
            m = re.match(r'try_begin_label_(\d+)', label)
            if m:
                n_id = m.group(1)
                try_regions.setdefault(n_id, {'begin': None, 'end': None, 'handlers': []})
                try_regions[n_id]['begin'] = idx
            m = re.match(r'try_end_label_(\d+)', label)
            if m:
                n_id = m.group(1)
                try_regions.setdefault(n_id, {'begin': None, 'end': None, 'handlers': []})
                try_regions[n_id]['end'] = idx
            m = re.match(r'handler_begin_label_(\d+)_(\d+)', label)
            if m:
                n_id = m.group(1)
                try_regions.setdefault(n_id, {'begin': None, 'end': None, 'handlers': []})
                try_regions[n_id]['handlers'].append(idx)

        for region in try_regions.values():
            if region['begin'] is None or not region['handlers']:
                continue
            # 找到 try 区域入口所在的块
            try_start = region['begin']
            if try_start not in start_to_bid:
                # 找包含 try_start 的块
                try_bid = None
                for b in blocks:
                    if b.start_idx <= try_start < b.end_idx:
                        try_bid = b.id
                        break
            else:
                try_bid = start_to_bid[try_start]

            if try_bid is not None:
                for handler_idx in region['handlers']:
                    if handler_idx in start_to_bid:
                        handler_bid = start_to_bid[handler_idx]
                        # 添加 try入口→handler 的隐式边
                        if handler_bid not in blocks[try_bid].successors:
                            blocks[try_bid].successors.append(handler_bid)
                            blocks[handler_bid].predecessors.append(try_bid)

        return ControlFlowGraph(blocks, 0)

    def reachable_blocks(self) -> set:
        """
        BFS 可达性分析。
        从 entry 块和所有异常处理块出发，计算可达的块集合。
        """
        if not self.blocks:
            return set()

        visited = set()
        queue = [self.entry_id]

        # 异常处理块是隐式可达的 (异常边)
        for block in self.blocks:
            if block.is_handler:
                queue.append(block.id)

        while queue:
            bid = queue.pop(0)
            if bid in visited:
                continue
            visited.add(bid)
            for succ in self.blocks[bid].successors:
                if succ not in visited:
                    queue.append(succ)

        return visited

    def reverse_postorder(self) -> list:
        """
        DFS 逆后序遍历 — 数据流分析的最优处理顺序。
        保证: 在处理某块之前，其所有前驱 (除回边外) 已被处理。
        """
        if not self.blocks:
            return []

        visited = set()
        rpo = []

        def _dfs(bid):
            if bid in visited:
                return
            visited.add(bid)
            for succ in self.blocks[bid].successors:
                _dfs(succ)
            rpo.append(bid)

        # 从 entry 开始 DFS
        _dfs(self.entry_id)

        # 也处理异常处理块 (可能不从 entry 可达)
        for block in self.blocks:
            if block.is_handler:
                _dfs(block.id)

        rpo.reverse()
        return rpo

    def stats(self) -> dict:
        """返回 CFG 统计信息"""
        reachable = self.reachable_blocks()
        return {
            'total_blocks': len(self.blocks),
            'reachable_blocks': len(reachable),
            'unreachable_blocks': len(self.blocks) - len(reachable),
            'handler_blocks': sum(1 for b in self.blocks if b.is_handler),
        }


# ============================================================
# 状态合并
# ============================================================

_UNKNOWN_TUPLE = ("unknown", "", "", "", "")


def _reg_to_tuple(reg) -> tuple:
    """RegState → 不可变 tuple 表示"""
    return (reg.kind, reg.module, reg.method,
            reg.factory_module, reg.factory_method)


def merge_states(states: list) -> BlockState:
    """
    合并多个前驱块的输出状态 (用于汇合点)。

    合并规则:
      - 所有前驱对某寄存器值一致 → 保留
      - 任何不一致 → unknown (保守)
    """
    if not states:
        return BlockState()

    if len(states) == 1:
        s = states[0]
        return BlockState(
            acc_kind=s.acc_kind, acc_module=s.acc_module,
            acc_method=s.acc_method,
            acc_factory_module=s.acc_factory_module,
            acc_factory_method=s.acc_factory_method,
            regs={k: v for k, v in s.regs.items()},
        )

    # 合并 ACC
    first = states[0]
    acc_tuple = (first.acc_kind, first.acc_module, first.acc_method,
                 first.acc_factory_module, first.acc_factory_method)
    for s in states[1:]:
        other = (s.acc_kind, s.acc_module, s.acc_method,
                 s.acc_factory_module, s.acc_factory_method)
        if other != acc_tuple:
            acc_tuple = _UNKNOWN_TUPLE
            break

    # 合并寄存器
    all_regs = set()
    for s in states:
        all_regs.update(s.regs.keys())

    merged_regs = {}
    for reg in all_regs:
        vals = [s.regs.get(reg, _UNKNOWN_TUPLE) for s in states]
        merged_regs[reg] = vals[0] if all(v == vals[0] for v in vals) else _UNKNOWN_TUPLE

    return BlockState(
        acc_kind=acc_tuple[0], acc_module=acc_tuple[1],
        acc_method=acc_tuple[2],
        acc_factory_module=acc_tuple[3], acc_factory_method=acc_tuple[4],
        regs=merged_regs,
    )
