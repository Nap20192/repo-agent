"""tool_window_callback: only the last `keep` tool results stay verbatim in the request."""

from google.adk.models.llm_request import LlmRequest
from google.genai import types

from scanner.app.callbacks import tool_window_callback


def _req(n: int) -> LlmRequest:
    contents = [types.Content(role="user", parts=[types.Part(text="go")])]
    for i in range(1, n + 1):
        contents.append(types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(
            id=f"c{i}", name="read_file", args={"path": f"f{i}.go", "start": 1, "end": 60}))]))
        contents.append(types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(
            id=f"c{i}", name="read_file", response={"text": "x" * (100 * i)}))]))
    return LlmRequest(contents=contents)


def _responses(req):
    return [p.function_response for c in req.contents for p in c.parts if p.function_response]


def test_window_digests_old_results_keeps_last_three():
    req = _req(5)
    cb = tool_window_callback(keep=3)
    assert cb(None, req) is None
    frs = _responses(req)
    assert [fr.id for fr in frs] == ["c1", "c2", "c3", "c4", "c5"]
    assert frs[0].response == {"digest": "read_file path=f1.go start=1 end=60: 100 chars"}
    assert frs[1].response["digest"].startswith("read_file path=f2.go")
    assert frs[2].response == {"text": "x" * 300} and frs[4].response == {"text": "x" * 500}
    assert req.contents[0].parts[0].text == "go"  # non-tool content untouched
    cb(None, req)  # idempotent
    assert _responses(req)[0].response == {"digest": "read_file path=f1.go start=1 end=60: 100 chars"}


def test_window_noop_when_few_results():
    req = _req(2)
    tool_window_callback(keep=3)(None, req)
    assert all("text" in fr.response for fr in _responses(req))
