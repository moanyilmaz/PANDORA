"""
多源协同分析与控制流子图提取 (subgraph.py)
=============================================
从调用图中识别隐私敏感 API 的协同调用关系，定位逻辑根节点，
提取带函数体的控制流子图，供下游意图推断模块消费。

三阶段算法:
  阶段一: 敏感节点标注 — 匹配规则库，按隐私类别分组
  阶段二: 语义根回溯 — 从敏感 API 逆向 BFS 到生命周期入口
  阶段三: 子图提取 — BFS 提取路径，附加函数体
"""

import json
import yaml
from dataclasses import dataclass, field
from collections import defaultdict, deque
from pathlib import Path

from .callgraph import CallGraph, CallEdge, EDGE_EXTERNAL_API, EDGE_IMPLICIT_UI
from .parser import PaFile, PaFunction


# ============================================================
# 阶段一: 敏感节点标注
# ============================================================

@dataclass
class SensitiveNode:
    """一个被标注为敏感的调用图节点"""
    node_name: str                  # 调用图中的节点名 (如 "@ohos:deviceInfo::brand")
    matched_rules: list = field(default_factory=list)  # 命中的规则 ID 列表
    categories: set = field(default_factory=set)        # 隐私类别集合


def load_rules(rules_path: str) -> dict:
    """
    加载隐私 API 规则库。
    返回 { "module::method": [rule_dict, ...] } 索引。
    """
    with open(rules_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    index = defaultdict(list)
    for rule in config.get('rules', []):
        key = f"{rule['module']}::{rule['method']}"
        index[key].append(rule)
    return dict(index)


def annotate_sensitive_nodes(cg: CallGraph, rules_index: dict) -> dict:
    """
    标注调用图中的敏感节点。

    Returns:
        { node_name: SensitiveNode } — 命中规则的节点映射
    """
    sensitive = {}
    for node_name, node in cg.nodes.items():
        if not node.is_external:
            continue
        if node_name in rules_index:
            sn = SensitiveNode(node_name=node_name)
            for rule in rules_index[node_name]:
                sn.matched_rules.append(rule['id'])
                sn.categories.add(rule['category'])
            sensitive[node_name] = sn
    return sensitive


def group_by_caller(cg: CallGraph, sensitive: dict) -> dict:
    """
    按共同调用者对敏感节点分组，识别协同关系。

    Returns:
        { caller_func_name: [SensitiveNode, ...] }
        仅包含调用了 >= 2 个敏感节点的调用者
    """
    # 初始化: 直接调用者 -> 其调用的敏感节点
    propagated = defaultdict(set)  # caller -> set of sn_names

    for sn_name, sn in sensitive.items():
        node = cg.nodes.get(sn_name)
        if not node:
            continue
        for edge in node.incoming:
            propagated[edge.caller].add(sn_name)

    # 向上传播: 如果函数 A 调用 B, B 关联敏感 API,
    # 那么 A 也间接关联该敏感 API。最多传播 5 层。
    MAX_DEPTH = 5
    for depth in range(MAX_DEPTH):
        updates = {}  # parent -> new sn_names to add
        # 对当前快照进行遍历，避免边迭代边修改
        snapshot = list(propagated.items())
        for func_name, sn_names in snapshot:
            func_node = cg.nodes.get(func_name)
            if not func_node:
                continue
            for edge in func_node.incoming:
                parent = edge.caller
                # 只传播 parent 尚未拥有的 sn_names
                existing = propagated.get(parent, set())
                new_sns = sn_names - existing
                if new_sns:
                    if parent not in updates:
                        updates[parent] = set()
                    updates[parent] |= new_sns

        if not updates:
            break
        for parent, new_sns in updates.items():
            propagated[parent] |= new_sns

    # 筛选: 仅保留关联了 >= 2 个不同敏感节点的调用者
    result = {}
    for caller, sn_names in propagated.items():
        if len(sn_names) >= 2:
            sns = [sensitive[n] for n in sn_names if n in sensitive]
            if len(sns) >= 2:
                result[caller] = sns

    return result


# ============================================================
# 阶段二: 语义根回溯 (生命周期入口追溯)
# ============================================================
#
# 新策略 (替代 SCC 缩点 + 支配树 LCA):
#   从敏感 API 的直接调用者出发，沿 incoming 边逆向 BFS，
#   直到命中 HarmonyOS 生命周期方法或无调用者的图根节点。
#   产出深层调用链 (如 onForeground -> Helper -> SensitiveAPI)，
#   为下游的意图/目的分析提供完整的行为上下文。
# ============================================================

# HarmonyOS 生命周期方法 / 入口函数关键词
# 命中任一关键词即视为语义入口
_LIFECYCLE_PATTERNS = {
    # --- Ability 生命周期 ---
    'onCreate', 'onDestroy', 'onForeground', 'onBackground',
    'onWindowStageCreate', 'onWindowStageDestroy',
    # --- UIAbility / Page 生命周期 ---
    'aboutToAppear', 'aboutToDisappear', 'onPageShow', 'onPageHide',
    'build', 'onReady',
    # --- UI 事件 ---
    'onClick', 'onTouch', 'onChange', 'onSubmit',
    'onSelect', 'onCheckedChange',
    # --- 服务/Worker ---
    'onConnect', 'onDisconnect', 'onRequest',
    'onMessage', 'onRemoteRequest',
    # --- 通用入口 ---
    'main', 'init', 'start', 'setup', 'run',
    'initialRender', 'reRender',
}


def _is_lifecycle_entry(func_name: str) -> bool:
    """
    判断函数名是否匹配生命周期入口特征。

    匹配规则:
      1. 函数全限定名中最后一个 '#' 分隔段包含关键词
      2. 或者 '.' 分隔的最后一段包含关键词
      3. 匹配不区分前缀哈希 (如 '#12345#onCreate' 匹配 'onCreate')
    """
    # 提取最后一段有意义的方法名
    # 格式可能是: com.example.Ability.#123#onCreate
    # 或: com.example.Ability.onCreate
    parts = func_name.replace('#', '.').split('.')
    # 过滤纯数字段 (哈希值)
    meaningful = [p for p in parts if p and not p.isdigit()]
    if not meaningful:
        return False

    # 检查最后几段是否包含生命周期关键词
    for part in meaningful[-3:]:
        if part in _LIFECYCLE_PATTERNS:
            return True
    return False


def _extract_module_prefix(func_name: str) -> str:
    """
    提取函数的页面/模块前缀。

    例如:
      'com.example.app.entry.ets.pages.deviceid.deviceid' -> 'com.example.app.entry.ets.pages.deviceid'
      'com.example.app.entry.ets.pages.deviceid.initialRender' -> 'com.example.app.entry.ets.pages.deviceid'
      'com.example.app.entry.ets.pages.deviceid.#123#callback' -> 'com.example.app.entry.ets.pages.deviceid'
    """
    # 去掉哈希前缀段 (如 #123#methodName -> methodName)
    last_dot = func_name.rfind('.')
    if last_dot == -1:
        return ''
    return func_name[:last_dot]


def _find_module_lifecycle_root(cg: CallGraph, func_name: str) -> str | None:
    """
    在同一页面模块下查找最高优先级的生命周期方法。
    (保留供高级分析使用，主流程使用 _collect_module_lifecycle)
    """
    lc_list = _collect_module_lifecycle(cg, func_name)
    return lc_list[0]['name'] if lc_list else None


def _collect_module_lifecycle(cg: CallGraph, func_name: str) -> list:
    """
    收集同一页面模块下的所有生命周期方法，作为子图上下文标注。

    ArkUI 声明式框架中, 同一 ViewPU 类下可能存在多种生命周期方法:
      - aboutToAppear: 页面显示前初始化 (数据预加载)
      - initialRender: 首次 UI 渲染 (组件构建)
      - build:         UI 重建 (响应式更新)
      - onClick:       用户交互回调 (按钮点击等)
      - onPageShow:    页面可见时回调
      - onCreate/onForeground: Ability 生命周期

    由于 ArkUI 通过 ViewPU 注册机制引用组件函数,
    调用图中不存在从这些方法到业务函数的直接调用边。
    因此无法精确判断哪个生命周期方法触发了特定的隐私行为。

    本函数返回所有候选生命周期方法, 按优先级排序,
    供下游意图推断模块综合判断。

    Returns:
        [{"name": full_name, "method": short_name, "out_degree": N}, ...]
        空列表如果没有找到任何生命周期方法
    """
    prefix = _extract_module_prefix(func_name)
    if not prefix:
        return []

    candidates = []
    for name, node in cg.nodes.items():
        if not name.startswith(prefix + '.') or node.is_external:
            continue
        if _is_lifecycle_entry(name):
            # 提取方法短名
            parts = name.replace('#', '.').split('.')
            meaningful = [p for p in parts if p and not p.isdigit()]
            method = meaningful[-1] if meaningful else name.split('.')[-1]
            candidates.append({
                'name': name,
                'method': method,
                'out_degree': len(node.outgoing),
            })

    if not candidates:
        return []

    # 按语义优先级排序
    priority_order = [
        'aboutToAppear', 'onPageShow', 'build',
        'initialRender', 'reRender',
        'onCreate', 'onForeground', 'onWindowStageCreate',
        'onClick', 'onConnect', 'onMessage',
    ]

    def _priority(item):
        try:
            return priority_order.index(item['method'])
        except ValueError:
            return len(priority_order)

    candidates.sort(key=_priority)
    return candidates


def find_semantic_roots(cg: CallGraph,
                       source_names: set,
                       max_backtrace_depth: int = 15) -> list:
    """
    从敏感 API 节点逆向 BFS，追溯到生命周期入口或图根节点。

    算法:
      1. 从每个 source 的直接内部调用者出发
      2. 沿 incoming 边逆向 BFS
      3. 遇到生命周期方法 → 标记为语义根 (优先)
      4. 遇到无调用者的图根节点 → 作为兜底入口
      5. 达到最大回溯深度 → 取当前最远节点为根
      6. 为每个子图收集同模块下所有生命周期方法作为上下文标注

    Returns:
        [(root_name, {source_names...}, [lifecycle_context...]), ...]
        每个元素: (语义根, 该根可达的敏感源集合, 同模块生命周期上下文列表)
    """
    # 收集所有直接调用敏感 API 的内部函数作为起点
    start_nodes = set()
    for sn_name in source_names:
        sn_node = cg.nodes.get(sn_name)
        if not sn_node:
            continue
        for edge in sn_node.incoming:
            caller_node = cg.nodes.get(edge.caller)
            if caller_node and not caller_node.is_external:
                start_nodes.add(edge.caller)

    if not start_nodes:
        return []

    # 对每个起点做逆向 BFS，找到语义根
    root_to_sources = defaultdict(set)
    root_to_lifecycle = {}  # root -> [lifecycle_context...]

    for start in start_nodes:
        # 该起点能直接调用的敏感源
        start_sources = set()
        start_node = cg.nodes.get(start)
        if start_node:
            for edge in start_node.outgoing:
                if edge.callee in source_names:
                    start_sources.add(edge.callee)

        if not start_sources:
            continue

        # 逆向 BFS 找语义根 (不做模块回退，保留原始调用者)
        semantic_root = _backtrace_to_entry(cg, start, max_backtrace_depth)
        root_to_sources[semantic_root].update(start_sources)

        # 收集同模块下的生命周期方法作为上下文标注
        if semantic_root not in root_to_lifecycle:
            lc_list = _collect_module_lifecycle(cg, semantic_root)
            root_to_lifecycle[semantic_root] = lc_list

    # 转为三元组列表
    return [(root, srcs, root_to_lifecycle.get(root, []))
            for root, srcs in root_to_sources.items()]


def _backtrace_to_entry(cg: CallGraph, start: str,
                         max_depth: int) -> str:
    """
    从 start 沿 incoming 边逆向 BFS，找到第一个语义入口。

    优先级:
      1. 命中生命周期关键词的函数 (最优，语义最强)
      2. 无调用者的图根节点 (兜底)
      3. 达到深度上限时取当前最远节点

    Returns:
        语义根节点名称
    """
    # 先检查 start 自身是否已经是入口
    if _is_lifecycle_entry(start):
        return start

    visited = {start}
    # (node_name, depth) 队列
    queue = deque([(start, 0)])
    best_root = start   # 兜底: 如果什么都找不到
    best_depth = 0

    while queue:
        current, depth = queue.popleft()

        if depth >= max_depth:
            continue

        node = cg.nodes.get(current)
        if not node:
            continue

        # 收集当前节点的所有内部调用者
        callers = []
        for edge in node.incoming:
            caller_node = cg.nodes.get(edge.caller)
            if caller_node and not caller_node.is_external and edge.caller not in visited:
                callers.append(edge.caller)

        # 如果当前节点无内部调用者 → 它是图根 (兜底入口)
        if not callers and depth > 0:
            return current

        for caller in callers:
            visited.add(caller)

            # 检查是否命中生命周期关键词
            if _is_lifecycle_entry(caller):
                return caller

            queue.append((caller, depth + 1))

            # 更新最远可达节点
            if depth + 1 > best_depth:
                best_depth = depth + 1
                best_root = caller

    return best_root


# ============================================================
# 保留: SCC 缩点 + 支配树 (供高级分析使用)
# ============================================================
#
# 算法流程:
#   1. Tarjan 算法识别强连通分量 (SCC), 消除调用图中的环路
#   2. 将 SCC 缩为超级节点, 构建严格 DAG
#   3. 在 DAG 上运行 CHK 支配树算法 (保证收敛)
#   4. 在支配树上计算 LCA, 映射回原节点
# ============================================================

def _build_reverse_adj(cg: CallGraph) -> dict:
    """构建反向邻接表: child -> set(parents)"""
    pred = defaultdict(set)
    succ = defaultdict(set)
    for edge in cg.edges:
        if not cg.nodes[edge.caller].is_external:
            succ[edge.caller].add(edge.callee)
            pred[edge.callee].add(edge.caller)
    return dict(succ), dict(pred)


def tarjan_scc(nodes: list, succ: dict) -> list:
    """
    Tarjan 算法识别强连通分量 (SCC) — 迭代版本。
    避免在大图 (1500+ 节点) 上递归导致 Python 栈溢出。

    Returns:
        list[set[str]] — 每个 SCC 是一个节点名集合, 按逆拓扑序排列
    """
    index_counter = 0
    tarjan_stack = []
    on_stack = set()
    index_map = {}
    lowlink = {}
    result = []

    for start in nodes:
        if start in index_map:
            continue

        # 迭代 DFS: 栈帧 = (node, iter(successors), caller_node_or_None)
        call_stack = [(start, iter(succ.get(start, [])), None)]
        index_map[start] = index_counter
        lowlink[start] = index_counter
        index_counter += 1
        tarjan_stack.append(start)
        on_stack.add(start)

        while call_stack:
            v, children_iter, parent = call_stack[-1]

            advanced = False
            for w in children_iter:
                if w not in index_map:
                    # 等同于递归调用 strongconnect(w)
                    index_map[w] = index_counter
                    lowlink[w] = index_counter
                    index_counter += 1
                    tarjan_stack.append(w)
                    on_stack.add(w)
                    call_stack.append((w, iter(succ.get(w, [])), v))
                    advanced = True
                    break
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index_map[w])

            if advanced:
                continue

            # 所有后继已访问完毕 (等同于递归返回)
            call_stack.pop()

            # 回传 lowlink 给父节点
            if parent is not None:
                lowlink[parent] = min(lowlink[parent], lowlink[v])

            # 检查是否是 SCC 的根
            if lowlink[v] == index_map[v]:
                scc = set()
                while True:
                    w = tarjan_stack.pop()
                    on_stack.discard(w)
                    scc.add(w)
                    if w == v:
                        break
                result.append(scc)

    return result


def contract_scc(sccs: list, succ: dict) -> tuple:
    """
    将 SCC 缩为超级节点, 构建 DAG。

    Returns:
        (dag_succ, dag_pred, node_to_scc_id, scc_id_to_members, scc_entries)
        - dag_succ: {scc_id: set(scc_id)}
        - dag_pred: {scc_id: set(scc_id)}
        - node_to_scc_id: {node_name: scc_id}
        - scc_id_to_members: {scc_id: set(node_name)}
        - scc_entries: {scc_id: entry_node} — 每个 SCC 的入口节点
    """
    # 为每个节点分配 SCC ID
    node_to_scc = {}
    scc_members = {}
    for i, scc in enumerate(sccs):
        scc_id = f"SCC_{i}"
        scc_members[scc_id] = scc
        for node in scc:
            node_to_scc[node] = scc_id

    # 构建 DAG 边
    dag_succ = defaultdict(set)
    dag_pred = defaultdict(set)

    for scc_id, members in scc_members.items():
        for node in members:
            for child in succ.get(node, []):
                child_scc = node_to_scc.get(child)
                if child_scc and child_scc != scc_id:
                    dag_succ[scc_id].add(child_scc)
                    dag_pred[child_scc].add(scc_id)

    # 确定每个 SCC 的入口节点 (有外部入边的成员, 或任意成员)
    scc_entries = {}
    for scc_id, members in scc_members.items():
        if len(members) == 1:
            scc_entries[scc_id] = next(iter(members))
        else:
            # 选择有来自其他 SCC 入边的成员作为入口
            best = None
            for node in members:
                for parent_scc in dag_pred.get(scc_id, []):
                    for parent_node in scc_members[parent_scc]:
                        if node in succ.get(parent_node, set()):
                            best = node
                            break
                    if best:
                        break
                if best:
                    break
            scc_entries[scc_id] = best or next(iter(members))

    return dict(dag_succ), dict(dag_pred), node_to_scc, scc_members, scc_entries


def _compute_rpo_dag(all_scc_ids: list, dag_succ: dict, roots: list) -> list:
    """在 DAG 上计算逆后序 (迭代 DFS)。"""
    visited = set()
    post_order = []

    def iterative_dfs(start):
        stack = [(start, iter(dag_succ.get(start, [])))]
        visited.add(start)
        while stack:
            node, children = stack[-1]
            try:
                child = next(children)
                if child not in visited:
                    visited.add(child)
                    stack.append((child, iter(dag_succ.get(child, []))))
            except StopIteration:
                stack.pop()
                post_order.append(node)

    for root in roots:
        if root not in visited:
            iterative_dfs(root)

    # 处理不可达节点
    for node in all_scc_ids:
        if node not in visited:
            iterative_dfs(node)

    return list(reversed(post_order))


def compute_dominators_dag(all_scc_ids: list, dag_succ: dict,
                           dag_pred: dict, roots: list) -> dict:
    """
    在 DAG 上运行 Cooper-Harvey-Kennedy (CHK) 支配树算法。
    DAG 无环, 保证收敛。

    对于多根 DAG，引入虚拟根节点 __VIRTUAL_ROOT__ 连接所有真实根，
    确保 intersect 函数在单根图上正确收敛。

    Returns:
        {scc_id: idom_scc_id} — 直接支配者映射
    """
    # ---- 引入虚拟根节点统一多根图 ----
    VIRTUAL_ROOT = "__VIRTUAL_ROOT__"
    aug_succ = dict(dag_succ)
    aug_pred = dict(dag_pred)
    aug_nodes = list(all_scc_ids) + [VIRTUAL_ROOT]

    # 虚拟根连接到所有真实根
    aug_succ[VIRTUAL_ROOT] = set(roots)
    for r in roots:
        if r not in aug_pred:
            aug_pred[r] = set()
        aug_pred[r].add(VIRTUAL_ROOT)

    # 单根 RPO
    rpo = _compute_rpo_dag(aug_nodes, aug_succ, [VIRTUAL_ROOT])
    rpo_index = {node: i for i, node in enumerate(rpo)}

    # 初始化: 只有虚拟根是自身的支配者
    idom = {VIRTUAL_ROOT: VIRTUAL_ROOT}

    def intersect(b1, b2):
        # 标准 CHK intersect, 单根保证收敛
        max_steps = len(rpo) * 2  # 安全上限
        steps = 0
        while b1 != b2 and steps < max_steps:
            while rpo_index.get(b1, 0) > rpo_index.get(b2, 0):
                b1 = idom.get(b1, VIRTUAL_ROOT)
                steps += 1
                if steps >= max_steps:
                    break
            while rpo_index.get(b2, 0) > rpo_index.get(b1, 0):
                b2 = idom.get(b2, VIRTUAL_ROOT)
                steps += 1
                if steps >= max_steps:
                    break
        return b1

    changed = True
    while changed:
        changed = False
        for node in rpo:
            if node == VIRTUAL_ROOT:
                continue
            preds = aug_pred.get(node, set())
            processed = [p for p in preds if p in idom]
            if not processed:
                continue
            new_idom = processed[0]
            for p in processed[1:]:
                new_idom = intersect(new_idom, p)
            if idom.get(node) != new_idom:
                idom[node] = new_idom
                changed = True

    # 移除虚拟根节点 — 各真实根的 idom 指向虚拟根, 改为自身
    for r in roots:
        if idom.get(r) == VIRTUAL_ROOT:
            idom[r] = r
    del idom[VIRTUAL_ROOT]

    return idom


def compute_lca_domtree(idom: dict, node_a: str, node_b: str) -> str:
    """
    在支配树上计算两个节点的最近公共祖先 (LCA)。

    通过同步向上回溯两个节点的支配链, 直到交汇。
    """
    # 收集 a 的支配链
    chain_a = set()
    cur = node_a
    visited = set()
    while cur and cur not in visited:
        chain_a.add(cur)
        visited.add(cur)
        parent = idom.get(cur)
        if parent == cur:
            break
        cur = parent

    # 沿 b 的支配链向上走, 找到第一个在 a 链上的节点
    cur = node_b
    visited = set()
    while cur and cur not in visited:
        if cur in chain_a:
            return cur
        visited.add(cur)
        parent = idom.get(cur)
        if parent == cur:
            break
        cur = parent

    # 无交汇, 返回根
    for r, d in idom.items():
        if r == d:
            return r
    return node_a


def find_dominator_roots(cg: CallGraph,
                         caller_to_sources: dict,
                         max_useful_depth: int = 8) -> list:
    """
    使用 SCC 缩点 + 支配树 + LCA 找到多个调用者的逻辑根节点。
    当所有调用者共享一个近距离 LCA 时, 返回单组；
    当 LCA 过高 (跨模块) 时, 按支配子树聚类, 返回多组。

    Args:
        cg: 调用图
        caller_to_sources: {caller_name: set(source_names)} 每个调用者关联的敏感源
        max_useful_depth: 支配链最大有用深度

    Returns:
        list[(root_name, set[source_names])]
        每个元素是一个 (根节点, 该根覆盖的敏感源集合)
    """
    callers = list(caller_to_sources.keys())

    if not callers:
        return []
    if len(callers) == 1:
        return [(callers[0], caller_to_sources[callers[0]])]

    # ---- 步骤 1-4: 构建支配树 (与之前相同) ----
    succ, pred = _build_reverse_adj(cg)
    internal_nodes = [n for n, node in cg.nodes.items() if not node.is_external]

    sccs = tarjan_scc(internal_nodes, succ)

    dag_succ, dag_pred, node_to_scc, scc_members, scc_entries = \
        contract_scc(sccs, succ)

    all_scc_ids = list(scc_members.keys())
    dag_roots = [s for s in all_scc_ids if not dag_pred.get(s)]
    if not dag_roots:
        dag_roots = [node_to_scc.get(callers[0], all_scc_ids[0])]

    idom = compute_dominators_dag(all_scc_ids, dag_succ, dag_pred, dag_roots)

    # ---- 步骤 5: 映射目标节点到 SCC ----
    caller_sccs = {}
    for c in callers:
        scc_id = node_to_scc.get(c)
        if scc_id:
            caller_sccs[c] = scc_id

    if not caller_sccs:
        return [(callers[0], set().union(*caller_to_sources.values()))]

    # ---- 步骤 6: 计算全局 LCA 并做质量检查 ----
    target_scc_list = list(caller_sccs.values())
    lca = target_scc_list[0]
    for s in target_scc_list[1:]:
        lca = compute_lca_domtree(idom, lca, s)

    def _domtree_dist_to(target_scc, anchor_scc):
        """从 target_scc 沿 idom 向上回溯到 anchor_scc 的距离"""
        depth = 0
        cur = target_scc
        seen = set()
        while cur != anchor_scc and cur not in seen and depth <= max_useful_depth:
            seen.add(cur)
            parent = idom.get(cur)
            if parent is None or parent == cur:
                return max_useful_depth + 1
            cur = parent
            depth += 1
        return depth if cur == anchor_scc else max_useful_depth + 1

    distances = [_domtree_dist_to(s, lca) for s in target_scc_list]
    lca_is_root = (idom.get(lca) == lca)

    # ---- 情况 A: LCA 有效 — 单组返回 ----
    if not lca_is_root and max(distances) <= max_useful_depth:
        all_sources = set()
        for sources in caller_to_sources.values():
            all_sources.update(sources)

        root = scc_entries.get(lca) or next(iter(scc_members.get(lca, {callers[0]})))
        return [(root, all_sources)]

    # ---- 情况 B: LCA 过高 — 按支配子树聚类 ----
    def _get_ancestor_at_depth(scc_id, depth):
        """获取 scc_id 在支配树中向上 depth 步的祖先"""
        cur = scc_id
        seen = set()
        for _ in range(depth):
            if cur in seen:
                break
            seen.add(cur)
            parent = idom.get(cur)
            if parent is None or parent == cur:
                break
            cur = parent
        return cur

    # 聚类: 按支配树中 depth=max_useful_depth 处的祖先分组
    # 同一祖先下的 callers 共享近距离支配者
    clusters = defaultdict(list)
    for caller_name, scc_id in caller_sccs.items():
        ancestor_key = _get_ancestor_at_depth(scc_id, max_useful_depth)
        clusters[ancestor_key].append(caller_name)

    # ---- 步骤 7: 为每个聚类计算局部 LCA → 生成分组结果 ----
    results = []

    for _ancestor_key, group_callers in clusters.items():
        # 合并该组的所有源节点
        group_sources = set()
        for c in group_callers:
            group_sources.update(caller_to_sources.get(c, set()))

        if len(group_callers) == 1:
            # 单一调用者, 直接用作根
            results.append((group_callers[0], group_sources))
            continue

        # 多个调用者, 计算组内 LCA
        group_scc_ids = [caller_sccs[c] for c in group_callers if c in caller_sccs]
        if not group_scc_ids:
            results.append((group_callers[0], group_sources))
            continue

        group_lca = group_scc_ids[0]
        for s in group_scc_ids[1:]:
            group_lca = compute_lca_domtree(idom, group_lca, s)

        # 验证组内 LCA 质量
        group_dists = [_domtree_dist_to(s, group_lca) for s in group_scc_ids]
        group_lca_is_root = (idom.get(group_lca) == group_lca)

        if not group_lca_is_root and max(group_dists) <= max_useful_depth:
            # 组内 LCA 有效
            root = scc_entries.get(group_lca) or \
                   next(iter(scc_members.get(group_lca, {group_callers[0]})))
            results.append((root, group_sources))
        else:
            # 组内 LCA 仍然无效 → 拆为单独的调用者
            for c in group_callers:
                results.append((c, caller_to_sources.get(c, set())))

    return results



# ============================================================
# 阶段三: 子图提取
# ============================================================

@dataclass
class SubgraphNode:
    """子图中的一个节点"""
    name: str
    node_type: str           # "internal" | "external_api"
    is_root: bool = False
    is_source: bool = False
    matched_rules: list = field(default_factory=list)
    categories: list = field(default_factory=list)
    function_body: dict | None = None  # 仅 internal 节点有


@dataclass
class SubgraphEdge:
    """子图中的一条边"""
    from_node: str
    to_node: str
    edge_type: str


@dataclass
class PrivacySubgraph:
    """一个隐私采集控制流子图"""
    id: str
    root: str
    privacy_categories: list
    source_nodes: list
    nodes: list          # [SubgraphNode, ...]
    edges: list          # [SubgraphEdge, ...]
    lifecycle_context: list = field(default_factory=list)  # 同模块生命周期上下文


def _get_function_body(func: PaFunction) -> dict:
    """提取函数体信息，用于子图输出"""
    instructions = []
    for inst in func.instructions:
        if inst.operands:
            instructions.append(f"{inst.opcode} {inst.operands}")
        else:
            instructions.append(inst.opcode)

    return {
        "params": func.params,
        "instruction_count": len(func.instructions),
        "instructions": instructions,
        "labels": dict(func.labels),
    }


def _build_func_index(pa: PaFile) -> dict:
    """构建函数名 -> PaFunction 的索引，避免 O(n) 线性扫描"""
    return {f.name: f for f in pa.functions}


def _find_function(func_index: dict, func_name: str) -> PaFunction | None:
    """通过索引查找函数定义 (O(1))"""
    return func_index.get(func_name)


def extract_subgraph(cg: CallGraph, root: str,
                     source_names: set, func_index: dict,
                     sensitive: dict, subgraph_id: str) -> PrivacySubgraph:
    """
    从 root 向下 BFS，提取到达所有 source 节点的路径子图。
    对内部函数节点附加函数体。

    Args:
        cg: 调用图
        root: 逻辑根节点
        source_names: 敏感 API 节点名称集合
        func_index: 函数名索引 (name -> PaFunction)
        sensitive: 敏感节点映射
        subgraph_id: 子图标识

    Returns:
        PrivacySubgraph 实例
    """
    # BFS 从 root 向下搜索
    visited = set()
    queue = deque([root])
    visited.add(root)

    sg_nodes = {}      # name -> SubgraphNode
    sg_edges = []       # [SubgraphEdge, ...]
    relevant_nodes = set()  # 在 root -> source 路径上的节点

    # 先用 BFS 找到所有可达节点
    reachable = set()
    bfs_q = deque([root])
    reachable.add(root)
    while bfs_q:
        current = bfs_q.popleft()
        node = cg.nodes.get(current)
        if not node:
            continue
        for edge in node.outgoing:
            if edge.callee not in reachable:
                reachable.add(edge.callee)
                bfs_q.append(edge.callee)

    # 从 source 节点反向 BFS，找到从 root 到 source 的路径上的节点
    backward_reachable = set()
    back_q = deque()
    for sn in source_names:
        if sn in reachable:
            backward_reachable.add(sn)
            back_q.append(sn)

    while back_q:
        current = back_q.popleft()
        node = cg.nodes.get(current)
        if not node:
            continue
        for edge in node.incoming:
            caller = edge.caller
            if caller in reachable and caller not in backward_reachable:
                backward_reachable.add(caller)
                back_q.append(caller)

    # 路径上的节点 = 正向可达 ∩ 反向可达
    relevant_nodes = reachable & backward_reachable

    # 构建子图节点
    all_categories = set()
    source_node_list = []

    for node_name in relevant_nodes:
        cg_node = cg.nodes.get(node_name)
        is_external = cg_node.is_external if cg_node else False

        sg_node = SubgraphNode(
            name=node_name,
            node_type="external_api" if is_external else "internal",
            is_root=(node_name == root),
            is_source=(node_name in source_names),
        )

        if node_name in sensitive:
            sn = sensitive[node_name]
            sg_node.matched_rules = list(sn.matched_rules)
            sg_node.categories = list(sn.categories)
            all_categories.update(sn.categories)
            source_node_list.append(node_name)

        # 附加函数体
        if not is_external:
            func = _find_function(func_index, node_name)
            if func:
                sg_node.function_body = _get_function_body(func)

        sg_nodes[node_name] = sg_node

    # 构建子图边 (仅保留两端都在子图中的边)
    for node_name in relevant_nodes:
        cg_node = cg.nodes.get(node_name)
        if not cg_node:
            continue
        for edge in cg_node.outgoing:
            if edge.callee in relevant_nodes:
                sg_edges.append(SubgraphEdge(
                    from_node=edge.caller,
                    to_node=edge.callee,
                    edge_type=edge.edge_type,
                ))

    return PrivacySubgraph(
        id=subgraph_id,
        root=root,
        privacy_categories=sorted(all_categories),
        source_nodes=sorted(source_node_list),
        nodes=list(sg_nodes.values()),
        edges=sg_edges,
    )


# ============================================================
# 主流程: 完整的三阶段管线
# ============================================================

def analyze_privacy_subgraphs(cg: CallGraph, pa: PaFile,
                              rules_path: str) -> list:
    """
    执行完整的三阶段分析管线。

    阶段一: 敏感节点标注 — 匹配规则库中的隐私 API
    阶段二: 语义根回溯 — 从敏感 API 逆向追溯到生命周期入口
    阶段三: 子图提取 — 从语义根 BFS 到敏感 API，提取完整调用链

    Args:
        cg: 已构建的调用图
        pa: 已解析的 PA 文件
        rules_path: 隐私 API 规则库路径

    Returns:
        [PrivacySubgraph, ...] 列表
    """
    import sys

    # 构建函数索引 (O(1) 查找)
    func_index = _build_func_index(pa)

    # ---- 阶段一: 敏感节点标注 ----
    rules_index = load_rules(rules_path)
    sensitive = annotate_sensitive_nodes(cg, rules_index)

    if not sensitive:
        return []

    all_source_names = set(sensitive.keys())
    print(f"[SUBGRAPH] {len(all_source_names)} sensitive API nodes found",
          file=sys.stderr)

    # ---- 阶段二: 语义根回溯 ----
    # 对所有敏感节点统一做逆向 BFS 找语义入口
    groups = find_semantic_roots(cg, all_source_names)

    print(f"[SUBGRAPH] {len(groups)} semantic roots found via backtrace",
          file=sys.stderr)

    # ---- 阶段三: 子图提取 ----
    subgraphs = []
    seen_roots = set()

    # 按覆盖敏感源数量降序排列 (协同组优先)
    sorted_groups = sorted(groups, key=lambda x: len(x[1]), reverse=True)

    for root, group_sources, lc_ctx in sorted_groups:
        if root is None:
            continue

        # 避免重复提取相同根的子图
        sg_key = (root, frozenset(group_sources))
        if sg_key in seen_roots:
            continue
        seen_roots.add(sg_key)

        # 判断子图类型: 覆盖 >= 2 个不同类别的源为协同子图
        cats = set()
        for sn_name in group_sources:
            if sn_name in sensitive:
                cats.update(sensitive[sn_name].categories)
        sg_type = "collab" if len(cats) >= 2 else "single"

        sg = extract_subgraph(
            cg, root, group_sources, func_index, sensitive,
            f"{sg_type}_{len(subgraphs)}"
        )
        if sg.nodes:
            sg.lifecycle_context = lc_ctx
            subgraphs.append(sg)

    # ---- 补充: 为未被任何子图覆盖的独立敏感节点生成子图 ----
    covered_sources = set()
    for sg in subgraphs:
        covered_sources.update(sg.source_nodes)

    for sn_name in all_source_names:
        if sn_name in covered_sources:
            continue
        sn_node = cg.nodes.get(sn_name)
        if not sn_node:
            continue
        # 为每个未覆盖的敏感源单独生成子图
        # 从其直接调用者回溯找语义根
        single_groups = find_semantic_roots(cg, {sn_name})
        for root, srcs, lc_ctx in single_groups:
            if root is None:
                continue
            sg_key = (root, frozenset(srcs))
            if sg_key in seen_roots:
                continue
            seen_roots.add(sg_key)
            sg = extract_subgraph(
                cg, root, srcs, func_index, sensitive,
                f"single_{len(subgraphs)}"
            )
            if sg.nodes:
                sg.lifecycle_context = lc_ctx
                subgraphs.append(sg)

    return subgraphs


# ============================================================
# 输出序列化
# ============================================================

def subgraph_to_dict(sg: PrivacySubgraph) -> dict:
    """将 PrivacySubgraph 转为可 JSON 序列化的字典"""
    nodes = []
    for n in sg.nodes:
        nd = {
            "name": n.name,
            "type": n.node_type,
            "is_root": n.is_root,
            "is_source": n.is_source,
        }
        if n.matched_rules:
            nd["matched_rules"] = n.matched_rules
        if n.categories:
            nd["categories"] = n.categories
        if n.function_body is not None:
            nd["function_body"] = n.function_body
        nodes.append(nd)

    edges = [
        {"from": e.from_node, "to": e.to_node, "type": e.edge_type}
        for e in sg.edges
    ]

    result = {
        "id": sg.id,
        "root": sg.root,
        "privacy_categories": sg.privacy_categories,
        "source_nodes": sg.source_nodes,
        "node_count": len(sg.nodes),
        "edge_count": len(sg.edges),
        "nodes": nodes,
        "edges": edges,
    }
    if sg.lifecycle_context:
        result["lifecycle_context"] = sg.lifecycle_context
    return result


def export_subgraphs(subgraphs: list, output_path: str):
    """将子图列表导出为 JSON 文件"""
    data = {
        "total_subgraphs": len(subgraphs),
        "summary": {
            "all_categories": sorted(set(
                cat for sg in subgraphs for cat in sg.privacy_categories
            )),
            "total_source_nodes": len(set(
                sn for sg in subgraphs for sn in sg.source_nodes
            )),
        },
        "subgraphs": [subgraph_to_dict(sg) for sg in subgraphs],
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return data


# ============================================================
# DOT 格式导出 (Graphviz 可视化)
# ============================================================

# 隐私类别对应的颜色
_CATEGORY_COLORS = {
    "DEVICE_INFO":       "#E74C3C",
    "PRECISE_LOCATION":  "#3498DB",
    "NETWORK_INFO":      "#2ECC71",
    "CLIPBOARD":         "#F39C12",
    "ACCOUNT_INFO":      "#9B59B6",
    "MICROPHONE":        "#E67E22",
    "CAMERA":            "#1ABC9C",
    "SENSOR_DATA":       "#E91E63",
    "CONTACTS":          "#00BCD4",
    "SMS":               "#FF5722",
    "ADVERTISING_ID":    "#795548",
}


def _dot_escape(s: str) -> str:
    """转义 DOT 标签中的特殊字符"""
    return s.replace('"', '\\"').replace('<', '\\<').replace('>', '\\>')


def _dot_node_label(node: dict) -> str:
    """为子图节点生成 DOT 标签"""
    name = node['name']
    # 取短名称
    short = name.rsplit('.', 1)[-1] if '.' in name else name
    if name.startswith('@'):
        # 外部 API: 显示完整模块::方法
        parts = name.split('::')
        if len(parts) == 2:
            module_short = parts[0].split('.')[-1] if '.' in parts[0] else parts[0]
            short = f"{module_short}::{parts[1]}"

    label_parts = [short]

    if node.get('categories'):
        cats = ", ".join(node['categories'])
        label_parts.append(f"[{cats}]")

    if node.get('function_body'):
        fb = node['function_body']
        label_parts.append(f"{fb['instruction_count']} instructions")

    return "\\n".join(label_parts)


def _subgraph_to_dot(sg: dict, index: int) -> str:
    """将单个子图转为 DOT 子图"""
    lines = []
    sg_id = sg['id']
    cats = ", ".join(sg['privacy_categories'])
    root = sg['root'].rsplit('.', 1)[-1]

    # 为整个子图选择一个颜色
    cat_color = "#888888"
    if sg['privacy_categories']:
        first_cat = sg['privacy_categories'][0]
        cat_color = _CATEGORY_COLORS.get(first_cat, "#888888")

    lines.append(f'  subgraph cluster_{sg_id} {{')
    lines.append(f'    label="{_dot_escape(sg_id)}: {_dot_escape(cats)}";')
    lines.append(f'    style=rounded;')
    lines.append(f'    color="{cat_color}";')
    lines.append(f'    fontcolor="{cat_color}";')
    lines.append(f'    fontname="Helvetica";')
    lines.append(f'    fontsize=11;')
    lines.append(f'')

    # 节点
    for node in sg['nodes']:
        node_id = f"{sg_id}_{node['name']}".replace('.', '_').replace(':', '_').replace('#', 'H').replace('/', '_')

        if node.get('is_root'):
            shape = "box"
            style = 'filled,bold'
            fillcolor = '#D5E8D4'
            fontcolor = '#2D7D2D'
        elif node.get('is_source'):
            shape = "box"
            style = 'filled'
            fillcolor = '#FFE6E6'
            fontcolor = '#CC0000'
        elif node['type'] == 'external_api':
            shape = "box"
            style = 'filled,dashed'
            fillcolor = '#E8E8E8'
            fontcolor = '#444444'
        else:
            shape = "box"
            style = 'filled'
            fillcolor = '#DAE8FC'
            fontcolor = '#1A5276'

        label = _dot_node_label(node)
        lines.append(
            f'    "{_dot_escape(node_id)}" ['
            f'label="{label}", '
            f'shape={shape}, style="{style}", '
            f'fillcolor="{fillcolor}", fontcolor="{fontcolor}", '
            f'fontname="Helvetica", fontsize=9'
            f'];'
        )

    lines.append(f'')

    # 边
    for edge in sg['edges']:
        from_id = f"{sg_id}_{edge['from']}".replace('.', '_').replace(':', '_').replace('#', 'H').replace('/', '_')
        to_id = f"{sg_id}_{edge['to']}".replace('.', '_').replace(':', '_').replace('#', 'H').replace('/', '_')

        edge_style = 'solid'
        edge_color = '#555555'
        if edge['type'] == 'definefunc':
            edge_style = 'dashed'
            edge_color = '#2980B9'
        elif edge['type'] == 'external_api':
            edge_color = '#C0392B'

        lines.append(
            f'    "{_dot_escape(from_id)}" -> "{_dot_escape(to_id)}" '
            f'[style={edge_style}, color="{edge_color}", '
            f'fontsize=8, fontname="Helvetica"];'
        )

    lines.append(f'  }}')
    return '\n'.join(lines)


def export_subgraphs_dot(subgraphs: list, output_path: str):
    """
    将子图列表导出为 DOT 文件 (Graphviz 格式)。

    可用以下命令渲染:
        dot -Tpng subgraphs.dot -o subgraphs.png
        dot -Tsvg subgraphs.dot -o subgraphs.svg
        dot -Tpdf subgraphs.dot -o subgraphs.pdf
    """
    # 先转为 dict 格式
    sg_dicts = [subgraph_to_dict(sg) for sg in subgraphs]

    lines = []
    lines.append('digraph PrivacySubgraphs {')
    lines.append('  rankdir=TB;')
    lines.append('  bgcolor="#FAFAFA";')
    lines.append('  node [margin=0.15];')
    lines.append('  edge [arrowsize=0.7];')
    lines.append('')

    # 图例
    lines.append('  subgraph cluster_legend {')
    lines.append('    label="Legend";')
    lines.append('    style=rounded;')
    lines.append('    color="#AAAAAA";')
    lines.append('    fontname="Helvetica";')
    lines.append('    fontsize=10;')
    lines.append('    _leg_root [label="Root\\n(entry point)", shape=box, style="filled,bold", fillcolor="#D5E8D4", fontcolor="#2D7D2D", fontname="Helvetica", fontsize=8];')
    lines.append('    _leg_source [label="Source\\n(sensitive API)", shape=box, style=filled, fillcolor="#FFE6E6", fontcolor="#CC0000", fontname="Helvetica", fontsize=8];')
    lines.append('    _leg_internal [label="Internal\\n(function)", shape=box, style=filled, fillcolor="#DAE8FC", fontcolor="#1A5276", fontname="Helvetica", fontsize=8];')
    lines.append('    _leg_root -> _leg_internal [style=invis];')
    lines.append('    _leg_internal -> _leg_source [style=invis];')
    lines.append('  }')
    lines.append('')

    for i, sg_dict in enumerate(sg_dicts):
        lines.append(_subgraph_to_dot(sg_dict, i))
        lines.append('')

    lines.append('}')

    dot_content = '\n'.join(lines)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(dot_content)

    return dot_content


# ============================================================
# CLI 入口: 独立运行完整管线
# ============================================================
if __name__ == "__main__":
    import sys
    import time
    import argparse
    from datetime import datetime
    from pathlib import Path

    arg_parser = argparse.ArgumentParser(
        description="PANDORA Subgraph Extractor - "
                    "从 PA 调用图中提取隐私敏感控制流子图"
    )
    arg_parser.add_argument("pa_file", help="Path to the .pa file")
    arg_parser.add_argument("--rules", "-r",
                            help="Path to rules YAML (default: rules/privacy_api_rules.yaml)")
    arg_parser.add_argument("--output", "-o",
                            help="Output directory (default: output/)")
    arg_parser.add_argument("--prefix", "-p",
                            help="Output filename prefix (default: subgraphs_<pa_stem>)")
    args = arg_parser.parse_args()

    pa_path = Path(args.pa_file)
    if not pa_path.exists():
        print(f"[ERROR] File not found: {pa_path}", file=sys.stderr)
        sys.exit(1)

    # 规则文件路径
    if args.rules:
        rules_path = args.rules
    else:
        # __file__ = pandora/core/subgraph.py → 项目根 = parent.parent.parent
        rules_path = str(Path(__file__).parent.parent.parent / "rules" / "privacy_api_rules.yaml")
    if not Path(rules_path).exists():
        print(f"[ERROR] Rules file not found: {rules_path}", file=sys.stderr)
        sys.exit(1)

    # 输出目录
    if args.output:
        out_dir = Path(args.output)
    else:
        out_dir = Path(__file__).parent.parent.parent / "output"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 文件名前缀
    prefix = args.prefix or f"subgraphs_{pa_path.stem}"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ---- 1. 解析 ----
    print(f"[PARSE] Loading {pa_path.name}...", file=sys.stderr)
    t0 = time.time()

    from .parser import parse_pa_file
    from .resolver import ModuleResolver
    from .callgraph import build_call_graph

    pa = parse_pa_file(str(pa_path))
    resolver = ModuleResolver(pa)
    t_parse = time.time() - t0
    print(f"[PARSE] {len(pa.functions)} functions in {t_parse:.2f}s", file=sys.stderr)

    # ---- 2. 构建调用图 ----
    print(f"[CALLGRAPH] Building...", file=sys.stderr)
    t1 = time.time()
    cg = build_call_graph(pa, import_resolver=resolver)
    t_cg = time.time() - t1
    print(f"[CALLGRAPH] {len(cg.nodes)} nodes, {len(cg.edges)} edges in {t_cg:.2f}s",
          file=sys.stderr)

    # ---- 3. 子图提取 ----
    print(f"[SUBGRAPH] Extracting...", file=sys.stderr)
    t2 = time.time()
    subgraphs = analyze_privacy_subgraphs(cg, pa, rules_path)
    t_sg = time.time() - t2

    # ---- 4. 导出 JSON ----
    json_path = out_dir / f"{prefix}_{timestamp}.json"
    data = export_subgraphs(subgraphs, str(json_path))

    # ---- 5. 导出 DOT ----
    dot_path = out_dir / f"{prefix}_{timestamp}.dot"
    export_subgraphs_dot(subgraphs, str(dot_path))

    # ---- 6. 汇总 ----
    elapsed = time.time() - t0
    all_cats = sorted(data['summary']['all_categories'])
    total_sources = data['summary']['total_source_nodes']

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"[DONE] {len(subgraphs)} subgraphs extracted in {elapsed:.2f}s", file=sys.stderr)
    print(f"  Categories ({len(all_cats)}): {', '.join(all_cats)}", file=sys.stderr)
    print(f"  Source nodes: {total_sources}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    for sg in subgraphs:
        cats = ", ".join(sg.privacy_categories)
        root_short = sg.root.rsplit('.', 1)[-1]
        fb = sum(1 for n in sg.nodes if n.function_body is not None)
        total = len(sg.nodes)
        print(f"  {sg.id:12s}  root={root_short}", file=sys.stderr)
        print(f"               [{cats}] "
              f"nodes={total}, edges={len(sg.edges)}, with_body={fb}",
              file=sys.stderr)

    print(f"\n[OUTPUT] JSON -> {json_path}", file=sys.stderr)
    print(f"[OUTPUT] DOT  -> {dot_path}", file=sys.stderr)
    print(f"\n[TIP] Render DOT: dot -Tpng {dot_path.name} -o {prefix}.png", file=sys.stderr)

