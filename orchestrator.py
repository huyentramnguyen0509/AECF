"""
Orchestrator — Algorithm 1 & 2, Chương 3.7.
"""

from __future__ import annotations
import argparse, json, os, time
from rich.console import Console
from rich.panel import Panel

from core.state import PentestState
from core.memory import SessionMemory, FailureMemory
from core.planner import AdaptivePlanningEngine
from agents.llm_client import LLMClient, DryRunLLMClient
from agents.agents import ReconAnalyzerAgent, PlannerAgent, ExecutionEvaluatorAgent, MemoryAgent
from storage.json_store import save_state

console = Console()


def _save_experiment_record(state, llm, condition, replans, exec_time, goal_reached,
                             out_dir="experiments/runs", scenario_key=None):
    os.makedirs(out_dir, exist_ok=True)
    usage = llm.usage_summary()
    record = {
        "experiment_id": state.session_id, "scenario": scenario_key or "default",
        "condition": condition, "target": state.target_name, "goal": state.goal,
        "success": bool(goal_reached), "steps": len(state.history.actions), "replans": replans,
        "execution_time_sec": round(exec_time, 2), **usage,
        "actions": [{"step_index": a.step_index, "action_type": a.action_type,
                     "target_vuln_id": a.target_vuln_id, "success": a.success,
                     "result_summary": a.result_summary, "reasoning": a.reasoning}
                    for a in state.history.actions],
        "chain": [a.action_type for a in state.history.actions if a.success],
    }
    path = os.path.join(out_dir, f"{state.target_name}_{state.session_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)
    return path


def run_session(target_url, target_name, goal, max_steps, use_memory=True,
                 log_path="storage/runs", condition=None, dry_run=False,
                 scenario_key=None, scenario_vuln_types=None):
    state = PentestState.new(target_base_url=target_url, target_name=target_name, goal=goal)

    llm = DryRunLLMClient() if dry_run else LLMClient()
    session_memory = SessionMemory(state.session_id)
    failure_memory = FailureMemory() if use_memory else FailureMemory().disabled_copy()

    recon = ReconAnalyzerAgent(state)
    engine = AdaptivePlanningEngine(llm, session_memory, failure_memory)
    planner = PlannerAgent(engine)
    executor = ExecutionEvaluatorAgent(state)
    memory_agent = MemoryAgent(session_memory, failure_memory)

    recon.seed_known_vuln_candidates(vuln_types=scenario_vuln_types)

    console.print(Panel.fit(
        f"[bold cyan]Phiên {state.session_id}[/bold cyan] — target=[yellow]{target_name}[/yellow] "
        f"scenario=[magenta]{scenario_key or 'default'}[/magenta] goal=[yellow]{goal}[/yellow] "
        f"mode=[magenta]{'DRY-RUN' if dry_run else 'LIVE'}[/magenta]",
        border_style="cyan"))

    t_start = time.time()
    step = 0
    replans = 0
    while step < max_steps and not planner.is_done(state):
        candidate = planner.next_action(state)
        if candidate is None:
            console.print(f"[yellow]Step {step}: Không còn candidate nào khả dụng — dừng.[/yellow]")
            break

        console.print(f"[bold]Step {step}:[/bold] Chọn: [cyan]{candidate.vuln.type.value}[/cyan] qua "
                       f"[cyan]{candidate.action_type}[/cyan] (score=[yellow]{candidate.final_score:.2f}[/yellow])")
        console.print(f"           [dim]Reasoning: {candidate.reasoning.strip()}[/dim]")

        record = executor.execute(candidate)
        memory_agent.update(state, record)

        if record.success:
            console.print(f"           -> [bold green]THÀNH CÔNG[/bold green]: {record.result_summary}")
        else:
            console.print(f"           -> [bold red]THẤT BẠI[/bold red]: {record.result_summary}")

        if not record.success:
            console.print(f"[yellow]Step {step}: Re-planning sau thất bại...[/yellow]")
            planner.replan(state, candidate, note=record.result_summary)
            replans += 1

        step += 1
        time.sleep(0.5)
    exec_time = time.time() - t_start

    goal_reached = planner.is_done(state)
    usage = llm.usage_summary()
    result_color = "green" if goal_reached else "red"
    console.print(Panel.fit(
        f"Kết thúc phiên [cyan]{state.session_id}[/cyan] sau [yellow]{step}[/yellow] bước\n"
        f"Goal đạt được: [bold {result_color}]{goal_reached}[/bold {result_color}]\n"
        f"Privilege cuối: [yellow]{state.privilege.current_level.value}[/yellow]\n"
        f"LLM usage: {usage['llm_calls']} calls, {usage['input_tokens']}+{usage['output_tokens']} tokens, "
        f"~[bold]${usage['estimated_cost_usd']}[/bold]",
        title="Session Summary", border_style=result_color))

    save_state(state, log_path)
    _save_experiment_record(state, llm, condition or ("full" if use_memory else "no_memory"),
                             replans, exec_time, goal_reached, scenario_key=scenario_key)
    return state


def main():
    from core.scenarios import SCENARIOS, get_scenario
    ap = argparse.ArgumentParser(description="Chạy Adaptive Exploit Chaining Framework")
    ap.add_argument("--target", required=True, help="Base URL target — nếu dùng --scenario, phải khớp đúng target_name của kịch bản đó (dvwa/juice_shop)")
    ap.add_argument("--name", default="dvwa", choices=["dvwa", "juice_shop", "other"])
    ap.add_argument("--goal", default="escalate_to_admin", choices=["escalate_to_admin", "data_leak"])
    ap.add_argument("--max-steps", type=int, default=15)
    ap.add_argument("--no-memory", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--scenario", choices=list(SCENARIOS.keys()), default=None)
    args = ap.parse_args()

    scenario_vuln_types = None
    goal = args.goal
    name = args.name
    if args.scenario:
        spec = get_scenario(args.scenario)
        scenario_vuln_types = spec.vuln_types
        goal = spec.goal
        name = spec.target_name
        if name != args.name:
            console.print(f"[yellow]Lưu ý: kịch bản {args.scenario} cần target_name='{name}', "
                           f"đã tự điều chỉnh --name (trước đó '{args.name}'). "
                           f"Đảm bảo --target bạn truyền đúng là URL của {name}.[/yellow]")

    run_session(target_url=args.target.rstrip("/"), target_name=name, goal=goal,
                max_steps=args.max_steps, use_memory=not args.no_memory, dry_run=args.dry_run,
                scenario_key=args.scenario, scenario_vuln_types=scenario_vuln_types)


if __name__ == "__main__":
    main()
