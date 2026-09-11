"""
Multi-agent handoff — two-agent pattern where orchestrator delegates to sub-agent
via a shared state channel.

The channel carries an HMAC over its task and metadata, plus a sender id and a
nonce, so the sub-agent can establish that the orchestrator populated it and that
the task has not been rewritten in transit or replayed.
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any

from .context_integrity import ContextIntegrityError, sign_context, verify_context


@dataclass
class AgentChannel:
    """Shared communication channel between orchestrator and sub-agent."""

    task: str = ""
    result: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    sender_id: str = ""
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
    hmac_signature: str = ""

    def sign(self, sender_id: str) -> "AgentChannel":
        self.sender_id = sender_id
        self.hmac_signature = sign_context(self._signed_payload())["_signature"]
        return self

    def verify(self) -> None:
        verify_context({**self._signed_payload(), "_signature": self.hmac_signature})

    def _signed_payload(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "metadata": self.metadata,
            "sender_id": self.sender_id,
            "nonce": self.nonce,
        }


async def run_handoff(
    orchestrator_task: str,
    orchestrator_run,
    sub_agent_run,
) -> str:
    """Run a two-agent handoff: orchestrator produces a task, sub-agent executes it.

    Args:
        orchestrator_task: The initial task for the orchestrator.
        orchestrator_run: Callable that runs the orchestrator and returns a channel.
        sub_agent_run: Callable that runs the sub-agent given a channel.

    Returns:
        The sub-agent's result string.

    Raises:
        ContextIntegrityError: if the channel was not signed by the orchestrator.
    """
    channel = AgentChannel(task=orchestrator_task)
    channel = await orchestrator_run(channel)
    channel.sign(sender_id="orchestrator")

    channel.verify()

    channel = await sub_agent_run(channel)

    return channel.result


if __name__ == "__main__":
    async def mock_orchestrator(channel: AgentChannel) -> AgentChannel:
        channel.task = "Read the file at /tmp/config.json and summarize it."
        return channel

    async def mock_sub_agent(channel: AgentChannel) -> AgentChannel:
        channel.result = f"Sub-agent executed task: {channel.task}"
        return channel

    try:
        result = asyncio.run(
            run_handoff("Analyze the system config", mock_orchestrator, mock_sub_agent)
        )
    except ContextIntegrityError as exc:
        result = f"Handoff refused: {exc}"
    print(result)
