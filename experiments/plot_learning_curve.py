"""
Learning Curve — minh hoạ đóng góp của Failure Memory (RQ3).

Vẽ replanning_count theo thứ tự trial cho full vs no_memory.
"""

from __future__ import annotations
import argparse
import pandas as pd
import matplotlib.pyplot as plt

CSV_PATH = "storage/experiments_raw.csv"


def plot_learning_curve(csv_path=CSV_PATH, scenario=None, out_path="storage/learning_curve.png"):
    df = pd.read_csv(csv_path)
    if scenario and "scenario" in df.columns:
        df = df[df["scenario"] == scenario]

    df = df[df["condition"].isin(["full", "no_memory"])].sort_values(["condition", "trial"])

    fig, ax = plt.subplots(figsize=(8, 5))
    for condition, color, label in [
        ("full", "green", "Full Framework (có Memory)"),
        ("no_memory", "red", "Planning-only (không Memory)"),
    ]:
        sub = df[df["condition"] == condition]
        if sub.empty:
            continue
        grouped = sub.groupby("trial")["replanning_count"].mean().reset_index()
        ax.plot(grouped["trial"], grouped["replanning_count"], marker="o", color=color, label=label)

    ax.set_xlabel("Trial (thứ tự lần lặp)")
    ax.set_ylabel("Re-planning Count")
    title = "Learning Curve — Re-planning Count qua các trial"
    if scenario:
        title += f"\n({scenario})"
    ax.set_title(title)
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=CSV_PATH)
    ap.add_argument("--scenario", default=None)
    ap.add_argument("--out", default="storage/learning_curve.png")
    args = ap.parse_args()

    path = plot_learning_curve(args.csv, args.scenario, args.out)
    print(f"Đã lưu learning curve vào {path}")


if __name__ == "__main__":
    main()
