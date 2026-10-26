"""
Sinh dữ liệu thực nghiệm Chương 5 — chạy đủ 4 kịch bản (5.2.1-5.2.4) x 3
điều kiện ablation. Mỗi kịch bản tự route sang đúng target (DVWA hoặc
Juice Shop) theo core/scenarios.py — cần CẢ 2 container cùng chạy song song.
"""

from __future__ import annotations
import argparse, csv, json, os, time
from rich.console import Console

from orchestrator import run_session, _save_experiment_record
from core.state import VulnStatus
from core.scenarios import SCENARIOS, get_scenario

console = Console()

CONDITIONS = ["full", "no_memory", "static"]
CSV_PATH = "storage/experiments_raw.csv"
FIELDS = [
    "scenario", "condition", "trial", "target_name", "goal",
    "success", "planning_time_sec", "replanning_count",
    "exploit_chain_length", "coverage", "exploit_efficiency",
    "llm_calls", "input_tokens", "output_tokens", "estimated_cost_usd",
    "llm_refusals", "llm_fallbacks", "llm_empty",
]

ACTION_TO_VULN_TYPE = {
    "sqlmap_scan": "sql_injection", "sqlmap_exploit": "sql_injection",
    "auth_bypass_probe": "authentication_bypass", "idor_probe": "idor_broken_access_control",
}


def _resolve_target_url(spec, target_dvwa, target_juiceshop):
    if spec.target_name == "juice_shop":
        if not target_juiceshop:
            raise ValueError(f"Kịch bản {spec.key} cần --target-juiceshop nhưng chưa truyền.")
        return target_juiceshop
    if not target_dvwa:
        raise ValueError(f"Kịch bản {spec.key} cần --target-dvwa nhưng chưa truyền.")
    return target_dvwa


def _static_workflow(target_url, target_name, goal, max_steps, vuln_types):
    from core.state import PentestState
    from agents.agents import ReconAnalyzerAgent, ExecutionEvaluatorAgent
    from core.planner import Candidate

    state = PentestState.new(target_base_url=target_url, target_name=target_name, goal=goal)
    recon = ReconAnalyzerAgent(state)
    recon.seed_known_vuln_candidates(vuln_types=vuln_types)
    executor = ExecutionEvaluatorAgent(state)

    fixed_order = ["sqlmap_scan", "auth_bypass_probe", "idor_probe"]
    step = 0
    for action_type in fixed_order:
        if step >= max_steps:
            break
        matching = [v for v in state.vulns.vulns.values()
                    if v.status not in (VulnStatus.EXPLOITED,)
                    and ACTION_TO_VULN_TYPE[action_type] == v.type.value]
        if not matching:
            continue
        cand = Candidate(vuln=matching[0], action_type=action_type, base_score=0.5, reasoning="static order")
        executor.execute(cand)
        step += 1
    return state


class _ZeroUsageLLM:
    model = "none"
    def usage_summary(self):
        return {"llm_calls": 0, "input_tokens": 0, "output_tokens": 0, "estimated_cost_usd": 0.0}


def run_one_trial(scenario_key, condition, target_dvwa, target_juiceshop, max_steps, dry_run=False):
    spec = get_scenario(scenario_key)
    target_url = _resolve_target_url(spec, target_dvwa, target_juiceshop)
    target_name = spec.target_name
    t0 = time.time()

    if condition == "static":
        state = _static_workflow(target_url, target_name, spec.goal, max_steps, spec.vuln_types)
        replanning_count = 0
        planning_time = time.time() - t0
        usage = _ZeroUsageLLM().usage_summary()
        _save_experiment_record(state, _ZeroUsageLLM(), condition, replanning_count, planning_time,
                                 goal_reached=(state.privilege.current_level.value == "admin"),
                                 scenario_key=scenario_key)
    else:
        state = run_session(
            target_url=target_url, target_name=target_name, goal=spec.goal,
            max_steps=max_steps, use_memory=(condition == "full"),
            log_path=f"storage/runs/{scenario_key}/{condition}", condition=condition, dry_run=dry_run,
            scenario_key=scenario_key, scenario_vuln_types=spec.vuln_types,
        )
        replanning_count = len(state.history.failures())
        planning_time = time.time() - t0
        run_files = sorted(f for f in os.listdir("experiments/runs")
                            if f.startswith(f"{target_name}_{state.session_id}"))
        with open(os.path.join("experiments/runs", run_files[-1]), "r", encoding="utf-8") as f:
            usage = json.load(f)

    n_actions = len(state.history.actions)
    n_success = sum(1 for a in state.history.actions if a.success)
    vuln_types_tried = {a.target_vuln_id for a in state.history.actions}

    return {
        "scenario": scenario_key, "condition": condition, "target_name": target_name, "goal": spec.goal,
        "success": int(state.privilege.current_level.value != "unauthenticated" and n_success > 0),
        "planning_time_sec": round(planning_time, 2), "replanning_count": replanning_count,
        "exploit_chain_length": n_actions,
        "coverage": round(len(vuln_types_tried) / max(len(state.vulns.vulns), 1), 2),
        "exploit_efficiency": round(n_success / n_actions, 2) if n_actions else 0.0,
        "llm_calls": usage.get("llm_calls", 0), "input_tokens": usage.get("input_tokens", 0),
        "output_tokens": usage.get("output_tokens", 0), "estimated_cost_usd": usage.get("estimated_cost_usd", 0.0),
        "llm_refusals": usage.get("llm_refusals", 0), "llm_fallbacks": usage.get("llm_fallbacks", 0),
        "llm_empty": usage.get("llm_empty", 0),
    }


def main():
    ap = argparse.ArgumentParser(description="Chạy toàn bộ ablation study cho Chương 5, đủ 4 kịch bản 5.2.x")
    ap.add_argument("--target-dvwa", default=None, help="URL DVWA, vd http://localhost:8080")
    ap.add_argument("--target-juiceshop", default=None, help="URL Juice Shop, vd http://localhost:3000")
    ap.add_argument("--max-steps", type=int, default=15)
    ap.add_argument("--repeats", type=int, default=8)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--budget-cap-usd", type=float, default=5.0)
    ap.add_argument("--scenario", choices=list(SCENARIOS.keys()), default=None)
    args = ap.parse_args()

    scenario_keys = [args.scenario] if args.scenario else list(SCENARIOS.keys())

    needed_targets = {get_scenario(k).target_name for k in scenario_keys}
    if "dvwa" in needed_targets and not args.target_dvwa:
        raise SystemExit("Thiếu --target-dvwa (có kịch bản cần chạy trên DVWA).")
    if "juice_shop" in needed_targets and not args.target_juiceshop:
        raise SystemExit("Thiếu --target-juiceshop (có kịch bản cần chạy trên Juice Shop).")

    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    write_header = not os.path.exists(CSV_PATH)

    spent_so_far = 0.0
    completed_llm_trials = 0
    stopped_early = False

    total_llm_trials = len(scenario_keys) * 2 * args.repeats
    console.print(f"[cyan]Kế hoạch: {len(scenario_keys)} kịch bản x 3 điều kiện x {args.repeats} lần lặp "
                  f"= {len(scenario_keys) * 3 * args.repeats} trial tổng ({total_llm_trials} trial có gọi LLM)[/cyan]")

    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if write_header:
            writer.writeheader()

        for scenario_key in scenario_keys:
            if stopped_early:
                break
            spec = get_scenario(scenario_key)
            console.print(f"\n[bold magenta]=== Kịch bản: {spec.label} ({scenario_key}) "
                          f"[target={spec.target_name}] ===[/bold magenta]")

            for condition in CONDITIONS:
                if stopped_early:
                    break
                for trial in range(1, args.repeats + 1):
                    if args.budget_cap_usd > 0 and condition != "static" and completed_llm_trials > 0:
                        avg_cost_per_trial = spent_so_far / completed_llm_trials
                        projected = spent_so_far + avg_cost_per_trial
                        if projected > args.budget_cap_usd:
                            console.print(f"\n[bold red]!!! DỪNG SỚM[/bold red]: đã tiêu ${spent_so_far:.4f}, "
                                          f"trial kế tiếp ước tính ${avg_cost_per_trial:.4f} sẽ vượt ngân sách "
                                          f"${args.budget_cap_usd:.2f}.")
                            stopped_early = True
                            break

                    console.print(f">>> scenario={scenario_key} condition={condition} trial={trial}/{args.repeats}"
                                  + (f" | đã tiêu ${spent_so_far:.4f}/${args.budget_cap_usd:.2f}"
                                     if args.budget_cap_usd > 0 else ""))
                    row = run_one_trial(scenario_key, condition, args.target_dvwa, args.target_juiceshop,
                                         args.max_steps, dry_run=args.dry_run)
                    row["trial"] = trial
                    writer.writerow(row)
                    f.flush()

                    if condition != "static":
                        spent_so_far += row["estimated_cost_usd"]
                        completed_llm_trials += 1

    console.print(f"\n[bold]Đã ghi raw data vào {CSV_PATH}.[/bold] Tổng chi phí batch này: ${spent_so_far:.4f}"
                  + (" (DỪNG SỚM do chạm ngân sách)" if stopped_early else "")
                  + ". Chạy summarize_results.py để ra bảng mean±std.")


if __name__ == "__main__":
    main()
