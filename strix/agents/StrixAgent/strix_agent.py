from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig


class StrixAgent(BaseAgent):
    # Default iterations per scan mode.  Deep mode gets a large budget so the
    # phase gate system can run 4 full phases without hitting the iteration cap.
    max_iterations = 10000

    # Map scan-mode names to iteration budgets and phase counts.
    _SCAN_MODE_CONFIGS: dict[str, dict] = {
        "quick":    {"max_iterations": 1000,  "max_phases": 2},
        "standard": {"max_iterations": 5000,  "max_phases": 3},
        "deep":     {"max_iterations": 10000, "max_phases": 4},
    }

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        # Apply scan-mode budget before super().__init__ reads self.max_iterations
        scan_mode = config.get("scan_mode", "deep")
        mode_cfg = self._SCAN_MODE_CONFIGS.get(scan_mode, self._SCAN_MODE_CONFIGS["deep"])
        if "max_iterations" not in config:
            self.max_iterations = mode_cfg["max_iterations"]

        super().__init__(config)

        # Configure phase count on the state after BaseAgent sets it up.
        # Only root agents use phases (sub-agents complete on first finish).
        if self.state.parent_id is None:
            self.state.max_phases = mode_cfg["max_phases"]

    # mooox-Agent Scans (Repo, local code, Url web_application, IP-Address )
    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        task_parts = []

        if repositories:
            task_parts.append("\n\nRepositories:")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\nLocal Codebases:")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\nURLs:")
            task_parts.extend(f"- {url}" for url in urls)

        if ip_addresses:
            task_parts.append("\n\nIP Addresses:")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)
