"""Checkpoint system for Strix scan resume feature.

Added for Resume Feature - Original behavior is 100% unchanged when
checkpoint_manager is not injected into the agent config.
"""

import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def _json_default(obj: Any) -> Any:
    """Fallback serialiser for objects json.dumps cannot handle natively."""
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return str(obj)


CHECKPOINT_VERSION = "1.0"


class CheckpointModel(BaseModel):
    """Pydantic model for a full scan checkpoint snapshot.

    Added for Resume Feature.
    """

    version: str = CHECKPOINT_VERSION
    run_name: str
    target_hash: str  # Short SHA-256 of sorted target strings — used for validation
    saved_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    # Agent loop progress
    iteration: int
    original_max_iterations: int  # The max that was set when the scan started

    # Full AgentState dump (messages, sandbox_id, sandbox_token, etc.)
    agent_state: dict[str, Any]

    # Tracer state needed to restore stats and replay findings
    tracer_chat_messages: list[dict[str, Any]] = Field(default_factory=list)
    tracer_vulnerability_reports: list[dict[str, Any]] = Field(default_factory=list)

    # Added for sub-agent persistence: full agent registry and tool execution log
    # tracer.agents  → every agent (root + sub) with status, name, task, parent_id
    # tracer.tool_executions → every tool call result across all agents
    tracer_agents: dict[str, Any] = Field(default_factory=dict)
    tracer_tool_executions: dict[str, Any] = Field(default_factory=dict)  # key is str(int)
    tracer_next_execution_id: int = 1  # restore the ID counter so new IDs don't collide

    # Original scan configuration (passed to execute_scan)
    scan_config: dict[str, Any] = Field(default_factory=dict)

    # Full AgentState dumps for every non-root, non-completed sub-agent.
    # Keyed by agent_id so they can be restored with their original IDs.
    sub_agent_states: dict[str, dict[str, Any]] = Field(default_factory=dict)


def compute_target_hash(targets_info: list[dict[str, Any]]) -> str:
    """Return a short stable hash of the target list for checkpoint validation.

    Added for Resume Feature.
    """
    target_strings = sorted(t.get("original", "") for t in (targets_info or []))
    combined = "|".join(target_strings)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


class CheckpointManager:
    """Saves and loads scan checkpoints to ``strix_runs/<run_name>/checkpoint.json``.

    All operations are *non-fatal*: any I/O error is logged as a warning and
    the scan continues normally.

    Added for Resume Feature.
    """

    def __init__(self, run_name: str, run_dir: Path) -> None:
        self.run_name = run_name
        self.run_dir = run_dir
        self.checkpoint_path = run_dir / "checkpoint.json"
        self._tmp_path = run_dir / "checkpoint.json.tmp"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def exists(self) -> bool:
        """Return True if a checkpoint file is present."""
        return self.checkpoint_path.exists()

    def save(
        self,
        agent_state: Any,
        tracer: Any | None,
        scan_config: dict[str, Any],
        target_hash: str,
        original_max_iterations: int,
    ) -> None:
        """Atomically persist the current scan state.

        Writes to a ``.tmp`` file then renames to prevent corruption during a
        crash mid-write.  All errors are non-fatal (warning only).
        """
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)

            state_dict: dict[str, Any] = (
                agent_state.model_dump(mode="json") if hasattr(agent_state, "model_dump") else {}
            )

            tracer_chat_messages: list[dict[str, Any]] = []
            tracer_vulnerability_reports: list[dict[str, Any]] = []
            tracer_agents: dict[str, Any] = {}
            tracer_tool_executions: dict[str, Any] = {}
            tracer_next_execution_id: int = 1
            if tracer:
                tracer_chat_messages = list(getattr(tracer, "chat_messages", []))
                tracer_vulnerability_reports = list(
                    getattr(tracer, "vulnerability_reports", [])
                )
                # Added for sub-agent persistence — capture full agent registry
                # and all tool execution records so sub-agents are fully restored
                tracer_agents = dict(getattr(tracer, "agents", {}))
                # tool_executions keys are ints; serialise as strings for JSON
                raw_execs = getattr(tracer, "tool_executions", {})
                tracer_tool_executions = {str(k): v for k, v in raw_execs.items()}
                tracer_next_execution_id = getattr(tracer, "_next_execution_id", 1)

            # Capture full AgentState for every running sub-agent so they
            # can be restored with their complete message history on resume.
            sub_agent_states: dict[str, Any] = {}
            try:
                from strix.tools.agents_graph import agents_graph_actions

                for sid, inst in list(agents_graph_actions._agent_instances.items()):
                    s = getattr(inst, "state", None)
                    if s is not None and s.parent_id is not None:
                        sub_agent_states[sid] = (
                            s.model_dump(mode="json") if hasattr(s, "model_dump") else {}
                        )
            except Exception:  # noqa: BLE001
                pass

            checkpoint = CheckpointModel(
                run_name=self.run_name,
                target_hash=target_hash,
                iteration=agent_state.iteration,
                original_max_iterations=original_max_iterations,
                agent_state=state_dict,
                tracer_chat_messages=tracer_chat_messages,
                tracer_vulnerability_reports=tracer_vulnerability_reports,
                tracer_agents=tracer_agents,
                tracer_tool_executions=tracer_tool_executions,
                tracer_next_execution_id=tracer_next_execution_id,
                scan_config=scan_config,
                sub_agent_states=sub_agent_states,
            )

            # Atomic write: .tmp → rename.  Use json.dumps with a fallback
            # serialiser so non-standard objects (datetime, Pydantic models,
            # etc.) never silently abort the save.
            json_str = json.dumps(
                checkpoint.model_dump(mode="json"), indent=2, default=_json_default
            )
            self._tmp_path.write_text(json_str, encoding="utf-8")
            os.rename(self._tmp_path, self.checkpoint_path)

        except Exception as e:  # noqa: BLE001
            logger.warning("[Resume] Checkpoint save failed (non-fatal): %s", e)

    def load(self) -> "CheckpointModel | None":
        """Load and parse the checkpoint file.

        Returns ``None`` and logs a warning on any error (corruption, missing
        file, version mismatch).
        """
        if not self.checkpoint_path.exists():
            return None
        try:
            raw = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            return CheckpointModel.model_validate(raw)
        except Exception as e:  # noqa: BLE001
            logger.warning("[Resume] Checkpoint load failed: %s", e)
            return None

    def delete(self) -> None:
        """Remove the checkpoint file (called when the scan finishes cleanly)."""
        try:
            if self.checkpoint_path.exists():
                self.checkpoint_path.unlink()
            if self._tmp_path.exists():
                self._tmp_path.unlink()
        except Exception as e:  # noqa: BLE001
            logger.warning("[Resume] Checkpoint delete failed (non-fatal): %s", e)
