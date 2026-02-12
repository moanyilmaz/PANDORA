"""
PA隐私API检测工具 (main.py)
===========================
CLI 入口，协调 解析 → 检测 → 输出 的完整流程。

用法:
  python main.py <file.pa>                  # 默认JSON输出到 output/ 目录
  python main.py <file.pa> --format table   # 表格输出到 stdout
  python main.py <file.pa> --output dir/    # 指定输出目录
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from pandora.core.parser import parse_pa_file
from pandora.core.resolver import ModuleResolver
from pandora.core.detector import ApiDetector, load_rules, RuleMatcher


def _generate_output_path(pa_path: Path, output_dir: str | None) -> Path:
    """
    生成输出文件路径: output/results_<pa前缀名>_<时间戳>.json
    例如: output/results_modules_20260212_192003.json
    """
    # pa文件前缀名 (去掉 .pa 扩展名)
    prefix = pa_path.stem

    # 时间戳
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 输出目录
    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = Path(__file__).parent / "output"

    out_dir.mkdir(parents=True, exist_ok=True)

    filename = f"results_{prefix}_{timestamp}.json"
    return out_dir / filename


def format_table(detections, unmatched):
    """格式化为可读文本表格"""
    lines = []
    lines.append("=" * 100)
    lines.append("PA Privacy API Detection Report")
    lines.append("=" * 100)

    if not detections:
        lines.append("\n  [INFO] No privacy-sensitive API calls detected.\n")
        return "\n".join(lines)

    # 按类别分组
    by_category = {}
    for d in detections:
        by_category.setdefault(d.category, []).append(d)

    for cat, items in sorted(by_category.items()):
        lines.append(f"\n--- {cat} ({len(items)} detections) ---")
        for d in items:
            short_func = d.function_name.split('.')[-1] if '.' in d.function_name else d.function_name
            # 取函数名最后两段
            parts = d.function_name.split('.')
            short_func = '.'.join(parts[-2:]) if len(parts) >= 2 else d.function_name

            ctx = f" ({d.context})" if d.context else ""
            lines.append(
                f"  [{d.paradigm:18s}] {d.module}.{d.method}"
                f"\n    {'':>21s} Function: {short_func}"
                f"\n    {'':>21s} Line: {d.line_no}"
                f"{ctx}"
            )

    # 未匹配调用
    if unmatched:
        lines.append(f"\n--- UNMATCHED CALLS ({len(unmatched)}) ---")
        seen = set()
        for u in unmatched:
            key = (u.module, u.method)
            if key not in seen:
                seen.add(key)
                lines.append(f"  {u.module}.{u.method}")

    lines.append("\n" + "=" * 100)
    lines.append(f"Total: {len(detections)} detections in "
                 f"{len(by_category)} categories")
    lines.append("=" * 100)
    return "\n".join(lines)


def format_json(detections, unmatched, pa, elapsed):
    """格式化为JSON输出"""
    return {
        "summary": {
            "total_detections": len(detections),
            "total_unmatched": len(unmatched),
            "categories": list(set(d.category for d in detections)),
            "total_functions_analyzed": len(pa.functions),
            "total_records": len(pa.records),
            "analysis_time_seconds": round(elapsed, 3),
        },
        "detections": [
            {
                "rule_id": d.rule_id,
                "module": d.module,
                "method": d.method,
                "paradigm": d.paradigm,
                "category": d.category,
                "description": d.description,
                "function_name": d.function_name,
                "line_no": d.line_no,
                "context": d.context,
            }
            for d in detections
        ],
        "unmatched_calls": [
            {
                "module": u.module,
                "method": u.method,
                "function_name": u.function_name,
                "line_no": u.line_no,
            }
            for u in unmatched
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="PANDORA: Panda Assembly Navigation for Detection of Opcode-level Rights Access - "
                    "Privacy API Analyzer for HarmonyOS .pa files"
    )
    parser.add_argument("pa_file", help="Path to the .pa file")
    parser.add_argument("--format", choices=["json", "table"], default="json",
                        help="Output format (default: json)")
    parser.add_argument("--output", "-o",
                        help="Output directory (default: output/)")
    parser.add_argument("--rules", help="Path to custom rules YAML file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show verbose parsing info")
    args = parser.parse_args()

    pa_path = Path(args.pa_file)
    if not pa_path.exists():
        print(f"[ERROR] File not found: {pa_path}", file=sys.stderr)
        sys.exit(1)

    rules_path = args.rules or str(Path(__file__).parent / "rules" / "privacy_api_rules.yaml")
    if not Path(rules_path).exists():
        print(f"[ERROR] Rules file not found: {rules_path}", file=sys.stderr)
        sys.exit(1)

    # ---- 1. 解析 .pa 文件 ----
    print(f"[PARSE] Loading {pa_path.name}...", file=sys.stderr)
    t0 = time.time()
    pa = parse_pa_file(str(pa_path))
    t_parse = time.time() - t0

    if args.verbose:
        print(f"[PARSE] Done in {t_parse:.2f}s: "
              f"{len(pa.module_literals)} module literals, "
              f"{len(pa.records)} records, "
              f"{len(pa.functions)} functions", file=sys.stderr)

    # ---- 2. 构建模块解析器 ----
    resolver = ModuleResolver(pa)

    # ---- 3. 加载规则并检测 ----
    rules = load_rules(rules_path)
    matcher = RuleMatcher(rules)
    detector = ApiDetector(pa, resolver, matcher)

    print(f"[DETECT] Analyzing {len(pa.functions)} functions with "
          f"{len(rules)} rules...", file=sys.stderr)
    t1 = time.time()
    results = detector.analyze_all()
    t_detect = time.time() - t1

    elapsed = time.time() - t0
    print(f"[DONE] {len(results)} detections found in {elapsed:.2f}s", file=sys.stderr)

    # ---- 4. 输出结果 ----
    if args.format == "table":
        output = format_table(results, detector.unmatched)
        print(output)
    else:
        data = format_json(results, detector.unmatched, pa, elapsed)
        output = json.dumps(data, ensure_ascii=False, indent=2)

        # 自动生成输出文件路径: output/results_<前缀>_<时间戳>.json
        out_path = _generate_output_path(pa_path, args.output)
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"[OUTPUT] Results written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()

