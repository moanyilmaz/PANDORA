"""
PA隐私API检测工具 (main.py)
===========================
CLI 入口，协调 解析 → 调用图 → 检测 → 子图提取 → 输出 的完整流程。

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
from pandora.core.callgraph import build_call_graph
from pandora.core.subgraph import (
    analyze_privacy_subgraphs, export_subgraphs, export_subgraphs_dot
)


def _generate_output_paths(pa_path: Path, output_dir: str | None) -> dict:
    """
    生成所有输出文件路径:
      - results_<prefix>_<timestamp>.json    (API 检测结果)
      - subgraphs_<prefix>_<timestamp>.json  (隐私子图 JSON)
      - subgraphs_<prefix>_<timestamp>.dot   (隐私子图 DOT)

    Returns:
        {"results": Path, "subgraphs_json": Path, "subgraphs_dot": Path}
    """
    prefix = pa_path.stem
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = Path(__file__).parent / "output"

    out_dir.mkdir(parents=True, exist_ok=True)

    return {
        "results": out_dir / f"results_{prefix}_{timestamp}.json",
        "subgraphs_json": out_dir / f"subgraphs_{prefix}_{timestamp}.json",
        "subgraphs_dot": out_dir / f"subgraphs_{prefix}_{timestamp}.dot",
    }


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
    parser.add_argument("--no-subgraph", action="store_true",
                        help="Skip subgraph extraction (faster, only output results JSON)")
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

    elapsed_detect = time.time() - t0
    print(f"[DETECT] {len(results)} detections found in {elapsed_detect:.2f}s",
          file=sys.stderr)

    # ---- 4. 构建调用图 + 子图提取 ----
    subgraphs = []

    if not args.no_subgraph:
        print(f"[CALLGRAPH] Building call graph...", file=sys.stderr)
        t2 = time.time()
        cg = build_call_graph(pa, import_resolver=resolver)
        t_cg = time.time() - t2
        stats = cg.stats()
        print(f"[CALLGRAPH] {stats['total_nodes']} nodes, "
              f"{stats['total_edges']} edges "
              f"({stats['internal_functions']} internal) in {t_cg:.2f}s",
              file=sys.stderr)

        print(f"[SUBGRAPH] Extracting privacy subgraphs "
              f"(SCC + dominator tree + clustering)...", file=sys.stderr)
        t3 = time.time()
        subgraphs = analyze_privacy_subgraphs(cg, pa, rules_path)
        t_subgraph = time.time() - t3

        collab = sum(1 for s in subgraphs if s.id.startswith("collab_"))
        single = sum(1 for s in subgraphs if s.id.startswith("single_"))
        all_cats = set()
        for sg in subgraphs:
            all_cats.update(sg.privacy_categories)

        print(f"[SUBGRAPH] {len(subgraphs)} subgraphs "
              f"({collab} collab, {single} single), "
              f"{len(all_cats)} categories in {t_subgraph:.2f}s",
              file=sys.stderr)

    elapsed_total = time.time() - t0
    print(f"[DONE] Total analysis completed in {elapsed_total:.2f}s",
          file=sys.stderr)

    # ---- 5. 输出结果 ----
    if args.format == "table":
        output = format_table(results, detector.unmatched)
        print(output)
    else:
        # 生成统一时间戳的输出路径
        paths = _generate_output_paths(pa_path, args.output)

        # 5a. 输出 API 检测结果 JSON
        data = format_json(results, detector.unmatched, pa, elapsed_total)
        output = json.dumps(data, ensure_ascii=False, indent=2)
        with open(paths["results"], 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"[OUTPUT] Results    -> {paths['results']}", file=sys.stderr)

        # 5b. 输出子图 JSON + DOT
        if subgraphs:
            export_subgraphs(subgraphs, str(paths["subgraphs_json"]))
            export_subgraphs_dot(subgraphs, str(paths["subgraphs_dot"]))
            print(f"[OUTPUT] Subgraphs  -> {paths['subgraphs_json']}",
                  file=sys.stderr)
            print(f"[OUTPUT] DOT graph  -> {paths['subgraphs_dot']}",
                  file=sys.stderr)


if __name__ == "__main__":
    main()
