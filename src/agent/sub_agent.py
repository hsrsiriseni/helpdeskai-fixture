"""
Sub-agent (task executor) — ReAct-style agent delegated to by the orchestrator.

Runs under the sub_agent capability set, verifies the signature on the context
handed to it, and loads a system prompt checked against a pinned digest.
"""

import os
from typing import Annotated, TypedDict

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AnyMessage, SystemMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from .authz import SUB_AGENT, reset_active_role, set_active_role
from .context_integrity import sign_context, verify_context
from .prompt_integrity import verify_prompt_hash


class SubAgentState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    result: str


SUB_AGENT_RECURSION_LIMIT = 10


def _load_sub_agent_prompt() -> str:
    """Load the sub-agent system prompt, verified against its pinned digest."""
    prompt_path = os.environ.get(
        "SUB_AGENT_SYSTEM_PROMPT_PATH", "prompts/sub_agent_system.md"
    )
    return verify_prompt_hash(
        prompt_path, os.environ.get("SUB_AGENT_SYSTEM_PROMPT_HASH", "")
    )


def create_sub_agent_node(tools: list[BaseTool]):
    """Build a sub-agent node function suitable for embedding in the orchestrator graph."""

    system_prompt = _load_sub_agent_prompt()
    llm = ChatAnthropic(model="claude-3-5-haiku-20241022")
    llm_with_tools = llm.bind_tools(tools)

    def call_model(state: SubAgentState) -> dict:
        messages = [SystemMessage(content=system_prompt)] + state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def should_continue(state: SubAgentState) -> str:
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "tools"
        # Capture the final response as the result.
        return END

    tool_node = ToolNode(tools)

    graph = StateGraph(SubAgentState)
    graph.add_node("agent", call_model)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", should_continue, ["tools", END])
    graph.add_edge("tools", "agent")

    compiled = graph.compile()

    def run_sub_agent(state: dict) -> dict:
        """Node function: runs the sub-agent and returns the result to the parent.

        Reads the task from the orchestrator's `delegate_to_sub_agent` tool call,
        runs the sub-agent ReAct loop, and emits a ToolMessage answering that call
        (required so the orchestrator's next model turn has a valid message history).
        """
        from langchain_core.messages import HumanMessage, ToolMessage

        verify_context(state.get("context", {}))

        last = state["messages"][-1]
        task = ""
        tool_call_id = None
        for call in getattr(last, "tool_calls", []) or []:
            if call["name"] == "delegate_to_sub_agent":
                task = call["args"].get("task", "")
                tool_call_id = call["id"]
                break
        if not task:
            task = state.get("context", {}).get("sub_agent_task", "")

        token = set_active_role(SUB_AGENT)
        try:
            result = compiled.invoke(
                {"messages": [HumanMessage(content=task)], "result": ""},
                {"recursion_limit": SUB_AGENT_RECURSION_LIMIT},
            )
        finally:
            reset_active_role(token)
        result_text = result["messages"][-1].content

        out: dict = {
            "context": sign_context(
                {
                    **verify_context(state.get("context", {})),
                    "sub_agent_result": result_text,
                }
            ),
        }
        if tool_call_id is not None:
            out["messages"] = [
                ToolMessage(content=str(result_text), tool_call_id=tool_call_id)
            ]
        return out

    return run_sub_agent
