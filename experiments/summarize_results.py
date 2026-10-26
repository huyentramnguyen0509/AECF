"""
Tổng hợp storage/experiments_raw.csv -> bảng mean ± std dev theo
(kịch bản, condition).
"""

from __future__ import annotations
import argparse
import pandas as pd
from rich.console import Console
from rich.table import Table

console = Console()

CSV_PATH = "storage/experiments_raw.csv"
METRICS = [
    "success", "planning_time_sec", "replanning_count",
    "exploit_chain_length", "coverage", "exploit_efficiency",
    "llm_calls", "input_tokens", "output_tokens", "estimated_cost_usd",
    "llm_refusals", "llm_fallbacks", "llm_empty",
]

PERFORMANCE_METRICS = [
    "success", "planning_time_sec", "replanning_count",
    "exploit_chain_length", "coverage", "exploit_efficiency",
]
COST_METRICS = ["llm_calls", "input_tokens", "output_tokens", "estimated_cost_usd"]
RELIABILITY_METRICS = ["llm_refusals", "llm_fallbacks", "llm_empty"]

METRIC_LABELS = {
    "success": "Success Rate",
    "planning_time_sec": "Planning Time (s)",
    "replanning_count": "Re-planning Count",
    "exploit_chain_length": "Chain Length",
    "coverage": "Coverage",
    "exploit_efficiency": "Exploit Efficiency",
    "llm_calls": "LLM Calls",
    "input_tokens": "Input Tokens",
    "output_tokens": "Output Tokens",
    "estimated_cost_usd": "Cost (USD)",
    "llm_refusals": "Safeguard Refusals",
    "llm_fallbacks": "Heuristic Fallbacks",
    "llm_empty": "Empty Responses",
}


def summarize(csv_path=CSV_PATH, by_scenario=True):
    df = pd.read_csv(csv_path)
    for _c in ("llm_refusals", "llm_fallbacks", "llm_empty"):
        if _c not in df.columns:
            df[_c] = 0
    group_cols = ["scenario", "condition"] if by_scenario and "scenario" in df.columns else ["condition"]
    agg = df.groupby(group_cols)[METRICS].agg(["mean", "std"])
    agg.columns = [f"{m}_{stat}" for m, stat in agg.columns]
    agg = agg.round(3).reset_index()
    return agg


def to_markdown_table(summary):
    return summary.to_markdown(index=False)


def _print_rich_table(summary, metrics, title, group_cols):
    table = Table(title=title, show_lines=True)
    for gc in group_cols:
        table.add_column(gc.capitalize(), style="cyan", no_wrap=(gc != "scenario"))
    for m in metrics:
        table.add_column(METRIC_LABELS.get(m, m), justify="right")

    for _, row in summary.iterrows():
        cells = []
        for gc in group_cols:
            val = str(row[gc])
            if gc == "scenario" and "_" in val:
                val = val.split("_")[0]
            cells.append(val)
        for m in metrics:
            mean = row.get(f"{m}_mean", float("nan"))
            std = row.get(f"{m}_std", float("nan"))
            std_str = f" ± {std:.3f}" if pd.notna(std) else ""
            cells.append(f"{mean:.3f}{std_str}")
        table.add_row(*cells)

    console.print(table)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=CSV_PATH)
    ap.add_argument("--out", default="storage/experiments_summary.csv")
    ap.add_argument("--plot", action="store_true")
    ap.add_argument("--overall", action="store_true")
    args = ap.parse_args()

    by_scenario = not args.overall
    summary = summarize(args.csv, by_scenario=by_scenario)
    summary.to_csv(args.out, index=False)

    group_cols = ["scenario", "condition"] if by_scenario and "scenario" in summary.columns else ["condition"]

    console.print()
    _print_rich_table(summary, PERFORMANCE_METRICS, "Performance Metrics (mean ± std)", group_cols)
    console.print()
    _print_rich_table(summary, COST_METRICS, "Cost & Usage Metrics (mean ± std)", group_cols)
    _print_rich_table(summary, RELIABILITY_METRICS, "Reliability Metrics (mean ± std)", group_cols)

    console.print(f"\n[dim]Bảng đầy đủ (Markdown, dùng cho Phụ lục C) đã lưu vào {args.out}[/dim]")

    df_raw = pd.read_csv(args.csv)
    total_cost = df_raw["estimated_cost_usd"].sum()
    total_calls = df_raw["llm_calls"].sum()
    console.print(f"\n[bold]Tổng chi phí API đã dùng qua toàn bộ thí nghiệm: ${total_cost:.4f}[/bold] "
                  f"({int(total_calls)} lượt gọi LLM). So với $5 credit: còn lại ~${5 - total_cost:.2f}.")

    if args.plot:
        import matplotlib.pyplot as plt
        overall = summarize(args.csv, by_scenario=False)
        fig, axes = plt.subplots(1, 3, figsize=(15, 4))
        for ax, metric in zip(axes, ["success_mean", "planning_time_sec_mean", "exploit_efficiency_mean"]):
            ax.bar(overall["condition"], overall[metric])
            ax.set_title(metric)
        plt.tight_layout()
        plt.savefig("storage/experiments_comparison.png", dpi=150)
        console.print("[green]Đã lưu biểu đồ tổng quan vào storage/experiments_comparison.png[/green]")

        if by_scenario and "scenario" in summary.columns:
            scenarios = summary["scenario"].unique()
            fig, axes = plt.subplots(1, len(scenarios), figsize=(5 * len(scenarios), 4), squeeze=False)
            for i, sc in enumerate(scenarios):
                sub = summary[summary["scenario"] == sc]
                axes[0][i].bar(sub["condition"], sub["success_mean"])
                axes[0][i].set_title(sc, fontsize=9)
                axes[0][i].set_ylim(0, 1.1)
            plt.tight_layout()
            plt.savefig("storage/experiments_by_scenario.png", dpi=150)
            console.print("[green]Đã lưu biểu đồ theo kịch bản vào storage/experiments_by_scenario.png[/green]")


if __name__ == "__main__":
    main()
