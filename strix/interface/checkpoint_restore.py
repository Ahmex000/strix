"""Shared helpers for restoring scan state from a checkpoint.

Used by both cli.py and tui.py to avoid code duplication.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any


def restore_sub_agents(checkpoint_data: Any, llm_config: Any) -> list[str]:
    """Spawn previously-running sub-agents from a checkpoint.

    Each sub-agent is restored with its saved AgentState, blocking flags
    reset, sandbox cleared, and a resume-context message injected.  Agents
    are started in topological order (parents before children) in daemon
    threads.

    Returns the list of agent_ids that were successfully restored.
    """
    from strix.agents.StrixAgent import StrixAgent
    from strix.agents.state import AgentState
    from strix.tools.agents_graph import agents_graph_actions

    sub_agent_states: dict[str, Any] = checkpoint_data.sub_agent_states or {}
    if not sub_agent_states:
        return []

    _memo: dict[str, int] = {}

    def _depth(aid: str) -> int:
        if aid in _memo:
            return _memo[aid]
        parent = sub_agent_states.get(aid, {}).get("parent_id")
        _memo[aid] = (
            0
            if (parent is None or parent not in sub_agent_states)
            else 1 + _depth(parent)
        )
        return _memo[aid]

    restored_ids: list[str] = []
    for agent_id in sorted(sub_agent_states.keys(), key=_depth):
        state_dict = sub_agent_states[agent_id]
        try:
            state = AgentState.model_validate(state_dict)
            state.waiting_for_input = False
            state.waiting_start_time = None
            state.stop_requested = False
            state.completed = False
            state.llm_failed = False
            state.sandbox_id = None
            state.sandbox_token = None
            state.sandbox_info = None
            state.max_iterations = state.iteration + checkpoint_data.original_max_iterations
            state.max_iterations_warning_sent = False
            state.add_message(
                "user",
                f"[SYSTEM - SUB-AGENT RESUMED]\n"
                f"You were interrupted at iteration {state.iteration}. "
                f"Your sandbox has been reset and a fresh one will be created. "
                f"Review your conversation history above and continue your task "
                f"from where you left off. "
                f"Call agent_finish only when your task is genuinely complete.",
            )

            agent_cfg: dict[str, Any] = {
                "llm_config": llm_config,
                "state": state,
                "is_resumed": True,
            }
            agent = StrixAgent(agent_cfg)

            def _run(a: Any = agent, s: Any = state) -> None:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(a.agent_loop(s.task))
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    loop.close()

            t = threading.Thread(
                target=_run,
                daemon=True,
                name=f"ResumedAgent-{state.agent_name}-{agent_id[:8]}",
            )
            t.start()
            with agents_graph_actions._agents_lock:
                agents_graph_actions._running_agents[agent_id] = t
            restored_ids.append(agent_id)

        except Exception:  # noqa: BLE001
            pass

    return restored_ids


def build_root_resume_message(
    state: Any,
    checkpoint_data: Any,
    restored_ids: list[str] | None = None,
) -> None:
    """Inject a user message telling the root agent what happened and what is live."""
    iteration = checkpoint_data.iteration
    sub_agent_states: dict[str, Any] = checkpoint_data.sub_agent_states or {}

    if restored_ids:
        lines = [
            "\n\nThe following sub-agents have been AUTOMATICALLY RESTORED and are "
            "already running. Communicate with them using their original IDs:"
        ]
        for aid in restored_ids:
            sd = sub_agent_states.get(aid, {})
            name = sd.get("agent_name", "sub-agent")
            task = (sd.get("task") or "")[:200]
            lines.append(f"  • {name}  (ID: {aid})  — task: {task}")
        lines.append("\nDo NOT re-spawn these agents — they are already active.")
        sub_agent_section = "\n".join(lines)
    else:
        dead: list[dict[str, Any]] = []
        for aid, node in (checkpoint_data.tracer_agents or {}).items():
            if node.get("parent_id") is None:
                continue
            status = node.get("status", "unknown")
            if status not in ("completed", "finished", "stopped", "error", "failed"):
                dead.append(
                    {"name": node.get("name", "sub-agent"), "task": (node.get("task") or "")[:300]}
                )
        if dead:
            lines = [
                "\n\nThe following sub-agents were active at interruption but could "
                "not be automatically restored. Re-spawn them if their work is incomplete:"
            ]
            for sa in dead:
                lines.append(f"  • {sa['name']}  (task: {sa['task']})")
            sub_agent_section = "\n".join(lines)
        else:
            sub_agent_section = ""

    msg = (
        f"[SYSTEM - SCAN RESUMED]\n"
        f"This penetration test was interrupted at iteration {iteration}. "
        f"A fresh sandbox will be created automatically.\n\n"
        f"CRITICAL: Any agent IDs that appear in the conversation history ABOVE "
        f"this message are from the old session and are DEAD — do not interact "
        f"with them. Only the agents listed below are currently alive."
        f"{sub_agent_section}\n\n"
        f"Review the conversation history to understand what has already been done, "
        f"then CONTINUE the penetration test. "
        f"Do NOT call finish_scan unless all testing is genuinely complete."
    )
    state.add_message("user", msg)
