from halcyon import tools as tools_mod
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.llm import FinalAnswer, ToolCall, ToolLLM
from halcyon.store import Store

MAX_STEPS = 8


def run(llm: ToolLLM, session_id: str, message: str, bank: Bank,
        store: Store, settings: Settings, module: str = "m5") -> tuple[str, list]:
    messages: list[dict] = [{"role": "user", "content": message}]
    calls: list = []
    for i in range(MAX_STEPS):
        step = llm.next_step(messages, tools_mod.SCHEMAS)
        if isinstance(step, FinalAnswer):
            return step.text, calls
        assert isinstance(step, ToolCall)
        call_id = f"call_{i}"
        result = tools_mod.execute(step.name, session_id, step.args, bank, store, settings)
        calls.append((step.name, step.args, result))
        messages.append({"role": "assistant", "tool_calls": [
            {"id": call_id, "name": step.name, "args": step.args}]})
        messages.append({"role": "tool", "tool_call_id": call_id, "name": step.name, "content": result})
    return "step limit reached", calls


async def run_mcp(llm, session_id: str, message: str, host, store, settings,  # type: ignore[no-untyped-def]
                   module: str = "m6") -> tuple[str, list]:
    from halcyon.llm import FinalAnswer, ToolCall

    host.approve(await host.list_tools())
    messages: list[dict] = [{"role": "user", "content": message}]
    calls: list = []
    for i in range(MAX_STEPS):
        schemas = await host.schemas_for_llm()
        step = llm.next_step(messages, schemas)
        if isinstance(step, FinalAnswer):
            return step.text, calls
        assert isinstance(step, ToolCall)
        result = await host.call(step.name, step.args)
        calls.append((step.name, step.args, result))
        cid = f"call_{i}"
        messages.append({"role": "assistant", "tool_calls": [
            {"id": cid, "name": step.name, "args": step.args}]})
        messages.append({"role": "tool", "tool_call_id": cid, "name": step.name, "content": result})
    return "step limit reached", calls
