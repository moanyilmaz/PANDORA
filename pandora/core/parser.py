"""
PA文件解析器 (pa_parser.py)
============================
将 .pa (Panda Assembly) 文件解析为结构化数据：
  - Literal Arrays (含 MODULE_REQUEST_ARRAY)
  - Records (含 moduleRecordIdx)
  - Functions (含指令序列)
"""

import re
from dataclasses import dataclass, field


# ============================================================
# 数据结构定义
# ============================================================

@dataclass
class ModuleImport:
    """一条模块导入声明"""
    tag: str            # "REGULAR_IMPORT" / "NAMESPACE_IMPORT" / "LOCAL_EXPORT"
    local_name: str     # 本地变量名, e.g. "pasteboard"
    import_name: str    # 导入名, e.g. "default"
    module_request: str # 模块请求路径, e.g. "@ohos:pasteboard"
    export_name: str = ""  # 仅 LOCAL_EXPORT 使用


@dataclass
class ModuleLiteralArray:
    """一个包含模块导入信息的Literal Array"""
    literal_id: str             # 数组ID, e.g. "658"
    hex_addr: str               # 十六进制地址, e.g. "0x2cf31"
    module_requests: dict       # {index: module_path}, e.g. {0: "@ohos:pasteboard"}
    regular_imports: list       # [ModuleImport, ...]
    local_exports: list = field(default_factory=list)  # [ModuleImport, ...]


@dataclass
class PaRecord:
    """一条 .record 定义"""
    name: str                   # e.g. "com.next.liny.linys1stnext.entry.ets.pages.Clipboard"
    module_record_idx: str      # e.g. "0x2cf31" (对应 ModuleLiteralArray.hex_addr)
    fields: dict = field(default_factory=dict)  # 其他字段


@dataclass
class Instruction:
    """一条PA指令"""
    line_no: int                # 在 .pa 文件中的行号
    opcode: str                 # 操作码, e.g. "ldexternalmodulevar"
    operands: str               # 原始操作数字符串
    raw_line: str               # 原始行内容


@dataclass
class PaFunction:
    """一个函数定义"""
    name: str                   # 完全限定名
    params: str                 # 参数列表原始字符串
    start_line: int             # 函数起始行号
    end_line: int               # 函数结束行号
    instructions: list = field(default_factory=list)  # [Instruction, ...]
    labels: dict = field(default_factory=dict)  # label_name -> instruction_index


@dataclass
class PaFile:
    """解析后的完整PA文件"""
    module_literals: list       # [ModuleLiteralArray, ...]
    records: list               # [PaRecord, ...]
    functions: list             # [PaFunction, ...]

    # 便捷索引 (在 build_indices 中构建)
    hex_to_literal: dict = field(default_factory=dict)   # hex_addr -> ModuleLiteralArray
    record_by_name: dict = field(default_factory=dict)   # record.name -> PaRecord

    def build_indices(self):
        self.hex_to_literal = {lit.hex_addr: lit for lit in self.module_literals}
        self.record_by_name = {rec.name: rec for rec in self.records}


# ============================================================
# 解析逻辑
# ============================================================

# 正则表达式 (预编译)
RE_LITERAL_HEADER = re.compile(
    r'^(\d+)\s+(0x[0-9a-fA-F]+)\s+\{\s*(\d+)\s+\['
)
RE_MODULE_REQ_ENTRY = re.compile(
    r'^\s+(\d+)\s*:\s*(.+?)\s*,?\s*$'
)
RE_MODULE_TAG_SIMPLE = re.compile(r'^\s*ModuleTag:\s*(\w+),\s*(.*);')
RE_RECORD_START = re.compile(
    r'^\.record\s+(\S+)\s*\{'
)
RE_RECORD_FIELD = re.compile(
    r'^\s+(u\d+|i\d+|u32|i32|u64|i64)\s+(\S+)\s*=\s*(\S+)'
)
RE_FUNCTION_START = re.compile(
    r'^\.function\s+\S+\s+(\S+)\(([^)]*)\)\s*(?:<\w+>)?\s*\{'
)
RE_INSTRUCTION = re.compile(
    r'^\t(\S+)(?:\s+(.*))?$'
)


def parse_pa_file(filepath: str) -> PaFile:
    """解析 .pa 文件，返回结构化 PaFile 对象"""
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    module_literals = []
    records = []
    functions = []

    # 检测文件分区
    section = "UNKNOWN"
    i = 0
    total = len(lines)

    while i < total:
        line = lines[i].rstrip('\r\n')

        # 检测分区标记
        if '# LITERALS' in line or '# STRING LITERALS' in line:
            section = "LITERALS"
            i += 1
            continue
        elif '# RECORDS' in line:
            section = "RECORDS"
            i += 1
            continue
        elif '# METHODS' in line:
            section = "METHODS"
            i += 1
            continue

        # 根据当前分区调用对应解析器
        if section == "LITERALS":
            lit, consumed = _try_parse_literal_array(lines, i)
            if lit is not None:
                module_literals.append(lit)
                i += consumed
                continue

        elif section == "RECORDS":
            rec, consumed = _try_parse_record(lines, i)
            if rec is not None:
                records.append(rec)
                i += consumed
                continue

        elif section == "METHODS":
            func, consumed = _try_parse_function(lines, i)
            if func is not None:
                functions.append(func)
                i += consumed
                continue

        i += 1

    pa = PaFile(
        module_literals=module_literals,
        records=records,
        functions=functions,
    )
    pa.build_indices()
    return pa


def _try_parse_literal_array(lines, start_idx):
    """尝试从 start_idx 位置解析一个 Literal Array 块。
    只保留含 MODULE_REQUEST_ARRAY 的块。
    返回 (ModuleLiteralArray | None, consumed_lines)。
    """
    line = lines[start_idx].rstrip('\r\n')
    m = RE_LITERAL_HEADER.match(line)
    if not m:
        return None, 1

    literal_id = m.group(1)
    hex_addr = m.group(2)

    # 扫描直到 ]} (结束)
    module_requests = {}
    regular_imports = []
    local_exports = []
    in_module_req = False
    has_module_data = False
    consumed = 1  # 已消费第一行

    i = start_idx + 1
    while i < len(lines):
        ln = lines[i].rstrip('\r\n')
        consumed += 1

        if ln.strip().startswith(']}'):
            break

        # MODULE_REQUEST_ARRAY 段
        if 'MODULE_REQUEST_ARRAY:' in ln:
            in_module_req = True
            has_module_data = True
            i += 1
            continue

        if in_module_req:
            if '};' in ln or ln.strip() == '};':
                in_module_req = False
                i += 1
                continue
            req_m = RE_MODULE_REQ_ENTRY.match(ln)
            if req_m:
                module_requests[int(req_m.group(1))] = req_m.group(2).strip()
            i += 1
            continue

        # ModuleTag 行
        if 'ModuleTag:' in ln:
            has_module_data = True
            tag_m = RE_MODULE_TAG_SIMPLE.match(ln.strip())
            if tag_m:
                tag_type = tag_m.group(1)
                rest = tag_m.group(2).strip()
                # 解析 "key: value, key: value" 格式的键值对
                kv = {}
                for part in rest.split(','):
                    part = part.strip()
                    if ':' in part:
                        k, v = part.split(':', 1)
                        kv[k.strip()] = v.strip()

                mi = ModuleImport(
                    tag=tag_type,
                    local_name=kv.get('local_name', ''),
                    import_name=kv.get('import_name', ''),
                    module_request=kv.get('module_request', ''),
                    export_name=kv.get('export_name', ''),
                )
                if tag_type == "LOCAL_EXPORT":
                    local_exports.append(mi)
                else:
                    regular_imports.append(mi)

        i += 1

    if not has_module_data:
        return None, consumed

    lit = ModuleLiteralArray(
        literal_id=literal_id,
        hex_addr=hex_addr,
        module_requests=module_requests,
        regular_imports=regular_imports,
        local_exports=local_exports,
    )
    return lit, consumed


def _try_parse_record(lines, start_idx):
    """尝试解析一个 .record 块"""
    line = lines[start_idx].rstrip('\r\n')
    m = RE_RECORD_START.match(line)
    if not m:
        return None, 1

    name = m.group(1)
    fields = {}
    module_record_idx = ""
    consumed = 1

    i = start_idx + 1
    while i < len(lines):
        ln = lines[i].rstrip('\r\n')
        consumed += 1

        if ln.strip() == '}':
            break

        fm = RE_RECORD_FIELD.match(ln)
        if fm:
            field_name = fm.group(2)
            field_value = fm.group(3)
            fields[field_name] = field_value
            if field_name == 'moduleRecordIdx':
                module_record_idx = field_value

        i += 1

    rec = PaRecord(
        name=name,
        module_record_idx=module_record_idx,
        fields=fields,
    )
    return rec, consumed


# 标签行正则: 匹配 jump_label_6:, try_begin_label_0:, handler_begin_label_0_0: 等
_RE_LABEL = re.compile(r'^([a-zA-Z_]\w*):$')


def _try_parse_function(lines, start_idx):
    """尝试解析一个 .function 块"""
    line = lines[start_idx].rstrip('\r\n')
    m = RE_FUNCTION_START.match(line)
    if not m:
        return None, 1

    func_name = m.group(1)
    params = m.group(2)
    start_line = start_idx + 1  # 1-indexed
    instructions = []
    labels = {}  # label_name -> instruction_index (标签指向下一条指令)
    consumed = 1

    i = start_idx + 1
    while i < len(lines):
        ln = lines[i].rstrip('\r\n')
        consumed += 1

        if ln.strip() == '}':
            break

        stripped = ln.strip()

        # 检查是否为标签行 (column 0 或 tab 级别, 以 : 结尾)
        label_m = _RE_LABEL.match(stripped)
        if label_m:
            # 标签指向下一条将被添加的指令
            labels[label_m.group(1)] = len(instructions)
            i += 1
            continue

        # 解析指令行 (以 tab 开头)
        if ln.startswith('\t'):
            inst_m = RE_INSTRUCTION.match(ln)
            if inst_m:
                opcode = inst_m.group(1)
                operands = inst_m.group(2) if inst_m.group(2) else ""
                instructions.append(Instruction(
                    line_no=i + 1,  # 转为 1-indexed
                    opcode=opcode,
                    operands=operands.strip(),
                    raw_line=ln,
                ))

        i += 1

    func = PaFunction(
        name=func_name,
        params=params,
        start_line=start_line,
        end_line=start_line + consumed - 1,
        instructions=instructions,
        labels=labels,
    )
    return func, consumed


# ============================================================
# 调试用: 独立运行时打印统计信息
# ============================================================
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python pa_parser.py <file.pa>")
        sys.exit(1)

    pa = parse_pa_file(sys.argv[1])
    print(f"[PARSED] Module Literals: {len(pa.module_literals)}")
    print(f"[PARSED] Records: {len(pa.records)}")
    print(f"[PARSED] Functions: {len(pa.functions)}")

    for lit in pa.module_literals[:3]:
        print(f"  Literal {lit.literal_id} @ {lit.hex_addr}: "
              f"{len(lit.module_requests)} requests, "
              f"{len(lit.regular_imports)} imports")
        for imp in lit.regular_imports:
            print(f"    {imp.local_name} <- {imp.module_request}")

    for rec in pa.records[:3]:
        print(f"  Record: {rec.name}, idx={rec.module_record_idx}")

    for func in pa.functions[:3]:
        print(f"  Function: {func.name}, "
              f"{len(func.instructions)} instructions")
