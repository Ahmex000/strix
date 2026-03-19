import atexit
import signal
import sys
import threading
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from strix.agents.StrixAgent import StrixAgent
from strix.llm.config import LLMConfig
from strix.telemetry.tracer import Tracer, set_global_tracer

from .utils import (
    build_live_stats_text,
    format_vulnerability_report,
)


# Added for Resume Feature — helpers for CLI resume banner and history replay

def _print_resume_banner(console: Console, run_name: str, iteration: int) -> None:
    """Print the resume banner so the user knows the scan is continuing."""
    resume_text = Text()
    resume_text.append("Resuming interrupted scan", style="bold #22c55e")
    resume_text.append("\n\n")
    resume_text.append("Run name  ", style="dim")
    resume_text.append(run_name, style="bold white")
    resume_text.append("\n")
    resume_text.append("Resuming from iteration  ", style="dim")
    resume_text.append(str(iteration), style="bold white")

    console.print(
        Panel(
            resume_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="#22c55e",
            padding=(1, 2),
        )
    )
    console.print()


def _replay_previous_output(
    console: Console, checkpoint_data: Any, display_vulnerability: Any
) -> None:
    """Re-render previous findings and key messages from the checkpoint.

    Added for Resume Feature — gives the user a sense of what was already
    discovered before the scan was interrupted.
    """
    # Replay vulnerability reports found so far
    for report in checkpoint_data.tracer_vulnerability_reports:
        report_id = report.get("id", "unknown")
        vuln_text = format_vulnerability_report(report)
        console.print(
            Panel(
                vuln_text,
                title=f"[bold red]{report_id.upper()} [dim](from previous session)[/]",
                title_align="left",
                border_style="dark_red",
                padding=(1, 2),
            )
        )
        console.print()

    # Print a summary of previous agent activity (last few assistant messages)
    chat_msgs = checkpoint_data.tracer_chat_messages
    assistant_msgs = [m for m in chat_msgs if m.get("role") == "assistant"]
    if assistant_msgs:
        last_msgs = assistant_msgs[-3:]
        history_text = Text()
        history_text.append("Last agent activity before interruption\n\n", style="dim")
        for msg in last_msgs:
            content = msg.get("content", "")
            if isinstance(content, str) and content.strip():
                # Truncate very long messages to keep replay readable
                snippet = content.strip()[:400]
                if len(content.strip()) > 400:
                    snippet += "…"
                history_text.append(snippet + "\n\n", style="dim white")

        if history_text.plain.strip():
            console.print(
                Panel(
                    history_text,
                    title="[dim]Previous session activity[/]",
                    title_align="left",
                    border_style="dim",
                    padding=(1, 2),
                )
            )
            console.print()


async def run_cli(args: Any) -> None:  # noqa: PLR0915
    console = Console()

    # Added for Resume Feature — detect resume and restore state
    checkpoint_data = getattr(args, "_checkpoint_data", None)
    is_resuming = getattr(args, "resume_from_checkpoint", False) and checkpoint_data is not None
    checkpoint_manager = getattr(args, "_checkpoint_manager", None)
    target_hash = getattr(args, "_target_hash", "")

    resumed_state = None
    if is_resuming:
        from strix.agents.state import AgentState

        resumed_state = AgentState.model_validate(checkpoint_data.agent_state)

        # Give the agent a fresh budget from the resume point so it never
        # stops just because it hit the original ceiling.
        # Added for Resume Feature — extend max_iterations dynamically.
        resumed_state.max_iterations = (
            resumed_state.iteration + checkpoint_data.original_max_iterations
        )
        resumed_state.max_iterations_warning_sent = False  # Reset warning flag

        # Clear sandbox — old container is gone, always start fresh
        resumed_state.sandbox_id = None
        resumed_state.sandbox_token = None
        resumed_state.sandbox_info = None

        # Fix: reset any blocking flags that were set when the scan was interrupted.
        # If the scan was paused mid-wait the restored state would still have
        # waiting_for_input=True / stop_requested=True and the loop would freeze.
        resumed_state.waiting_for_input = False
        resumed_state.waiting_start_time = None
        resumed_state.stop_requested = False
        resumed_state.completed = False
        resumed_state.llm_failed = False

    start_text = Text()
    if is_resuming:
        start_text.append("Penetration test resumed", style="bold #22c55e")
    else:
        start_text.append("Penetration test initiated", style="bold #22c55e")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    results_text = Text()
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(f"strix_runs/{args.run_name}", style="#60a5fa")

    note_text = Text()
    note_text.append("\n\n", style="dim")
    note_text.append("Vulnerabilities will be displayed in real-time.", style="dim")

    startup_panel = Panel(
        Text.assemble(
            start_text,
            "\n\n",
            target_text,
            "\n",
            results_text,
            note_text,
        ),
        title="[bold white]STRIX",
        title_align="left",
        border_style="#22c55e",
        padding=(1, 2),
    )

    console.print("\n")
    console.print(startup_panel)
    console.print()

    scan_mode = getattr(args, "scan_mode", "deep")

    scan_config = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
    }

    llm_config = LLMConfig(scan_mode=scan_mode)
    agent_config: dict[str, Any] = {
        "llm_config": llm_config,
        "max_iterations": 300,
    }

    if getattr(args, "local_sources", None):
        agent_config["local_sources"] = args.local_sources

    # Added for Resume Feature — inject checkpoint manager so the agent saves
    # state after every iteration.
    if checkpoint_manager:
        agent_config["checkpoint_manager"] = checkpoint_manager
        agent_config["target_hash"] = target_hash
        agent_config["scan_config"] = scan_config

    # Added for Resume Feature — pass restored state into the agent config
    if resumed_state is not None:
        agent_config["state"] = resumed_state

    tracer = Tracer(args.run_name)
    tracer.set_scan_config(scan_config)

    # Added for Resume Feature — restore conversation history and findings.
    # NOTE: We intentionally do NOT restore tracer.agents or tracer.tool_executions.
    # Injecting old sub-agent entries creates "ghost" agents: they appear in the
    # sidebar with no live instance, can't receive messages, and block real sub-agents
    # spawned in the new session from communicating with the root agent.
    # The root agent's full LLM context (in resumed_state.messages) already knows
    # what every sub-agent did — that is sufficient to continue correctly.
    if is_resuming and checkpoint_data:
        tracer.chat_messages.extend(checkpoint_data.tracer_chat_messages)
        tracer.vulnerability_reports.extend(checkpoint_data.tracer_vulnerability_reports)
        # Advance execution ID counter past old IDs to avoid collisions with
        # tool executions the live scan will create.
        if checkpoint_data.tracer_next_execution_id > tracer._next_execution_id:
            tracer._next_execution_id = checkpoint_data.tracer_next_execution_id

    # Added for Resume Feature — show resume banner + replay previous output
    if is_resuming and checkpoint_data:
        _print_resume_banner(console, args.run_name, checkpoint_data.iteration)
        _replay_previous_output(console, checkpoint_data, None)

    def display_vulnerability(report: dict[str, Any]) -> None:
        report_id = report.get("id", "unknown")

        vuln_text = format_vulnerability_report(report)

        vuln_panel = Panel(
            vuln_text,
            title=f"[bold red]{report_id.upper()}",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print(vuln_panel)
        console.print()

    tracer.vulnerability_found_callback = display_vulnerability

    def cleanup_on_exit() -> None:
        from strix.runtime import cleanup_runtime

        tracer.cleanup()
        cleanup_runtime()

    def signal_handler(_signum: int, _frame: Any) -> None:
        tracer.cleanup()
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_tracer(tracer)

    def create_live_status() -> Panel:
        status_text = Text()
        status_text.append("Penetration test in progress", style="bold #22c55e")
        status_text.append("\n\n")

        stats_text = build_live_stats_text(tracer, agent_config)
        if stats_text:
            status_text.append(stats_text)

        return Panel(
            status_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="#22c55e",
            padding=(1, 2),
        )

    try:
        console.print()

        with Live(
            create_live_status(), console=console, refresh_per_second=2, transient=False
        ) as live:
            stop_updates = threading.Event()

            def update_status() -> None:
                while not stop_updates.is_set():
                    try:
                        live.update(create_live_status())
                        time.sleep(2)
                    except Exception:  # noqa: BLE001
                        break

            update_thread = threading.Thread(target=update_status, daemon=True)
            update_thread.start()

            try:
                agent = StrixAgent(agent_config)
                result = await agent.execute_scan(scan_config)

                if isinstance(result, dict) and not result.get("success", True):
                    error_msg = result.get("error", "Unknown error")
                    error_details = result.get("details")
                    console.print()
                    console.print(f"[bold red]Penetration test failed:[/] {error_msg}")
                    if error_details:
                        console.print(f"[dim]{error_details}[/]")
                    console.print()
                    sys.exit(1)
            finally:
                stop_updates.set()
                update_thread.join(timeout=1)

    except Exception as e:
        console.print(f"[bold red]Error during penetration test:[/] {e}")
        raise

    if tracer.final_scan_result:
        console.print()

        final_report_text = Text()
        final_report_text.append("Penetration test summary", style="bold #60a5fa")

        final_report_panel = Panel(
            Text.assemble(
                final_report_text,
                "\n\n",
                tracer.final_scan_result,
            ),
            title="[bold white]STRIX",
            title_align="left",
            border_style="#60a5fa",
            padding=(1, 2),
        )

        console.print(final_report_panel)
        console.print()
