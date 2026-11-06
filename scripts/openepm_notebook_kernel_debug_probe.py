#!/usr/bin/env python3
"""Exercise an actual IPython-kernel breakpoint through Jupyter's DAP bridge."""
from __future__ import annotations

import json
import queue
import time

TIMEOUT = 30
CODE = "debug_marker = 41\ndebug_marker = debug_marker + 1\ndebug_result = debug_marker\n"


class DebugProbeError(RuntimeError):
    pass


def _deadline():
    return time.monotonic() + TIMEOUT


def _remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise DebugProbeError("NOTEBOOK_DEBUG_TIMEOUT")
    return value


def _debug_request(client, seq, command, arguments=None):
    content = {"seq": seq, "type": "request", "command": command,
               "arguments": arguments or {}}
    message = client.session.msg("debug_request", content)
    message_id = message["header"]["msg_id"]
    client.control_channel.send(message)
    deadline = _deadline()
    while True:
        reply = client.get_control_msg(timeout=_remaining(deadline))
        if reply.get("msg_type") == "debug_reply" and reply.get(
                "parent_header", {}).get("msg_id") == message_id:
            result = reply.get("content")
            if (not isinstance(result, dict) or result.get("success") is not True
                    or result.get("command") != command
                    or result.get("request_seq") != seq):
                raise DebugProbeError(f"NOTEBOOK_DEBUG_{command}_FAILED")
            return result


def _debug_event(client, event_name):
    deadline = _deadline()
    while True:
        message = client.get_iopub_msg(timeout=_remaining(deadline))
        if message.get("msg_type") != "debug_event":
            continue
        content = message.get("content")
        if isinstance(content, dict) and content.get("event") == event_name:
            return content


def _execute_reply(client, message_id):
    deadline = _deadline()
    while True:
        message = client.get_shell_msg(timeout=_remaining(deadline))
        if (message.get("msg_type") == "execute_reply"
                and message.get("parent_header", {}).get("msg_id") == message_id):
            if message.get("content", {}).get("status") != "ok":
                raise DebugProbeError("NOTEBOOK_DEBUG_EXECUTION_FAILED")
            return


def probe() -> dict:
    from jupyter_client import KernelManager

    manager = KernelManager(kernel_name="python3")
    manager.start_kernel()
    client = manager.client()
    client.start_channels()
    seq = 1
    try:
        client.wait_for_ready(timeout=TIMEOUT)
        initial = _debug_request(client, seq, "debugInfo"); seq += 1
        if initial.get("body", {}).get("isStarted") is not False:
            raise DebugProbeError("NOTEBOOK_DEBUG_INITIAL_STATE_INVALID")
        _debug_request(client, seq, "initialize", {
            "clientID": "openepm-qualification",
            "clientName": "Open EPM qualification",
            "adapterID": "python",
            "pathFormat": "path",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "supportsVariableType": True,
            "supportsVariablePaging": False,
            "supportsRunInTerminalRequest": False,
            "locale": "en-US"}); seq += 1
        _debug_request(client, seq, "attach", {"justMyCode": False}); seq += 1
        dumped = _debug_request(client, seq, "dumpCell", {"code": CODE}); seq += 1
        source_path = dumped.get("body", {}).get("sourcePath")
        if not isinstance(source_path, str) or not source_path.endswith(".py"):
            raise DebugProbeError("NOTEBOOK_DEBUG_SOURCE_PATH_INVALID")
        breakpoint = _debug_request(client, seq, "setBreakpoints", {
            "source": {"name": "openepm-debug-cell", "path": source_path},
            "breakpoints": [{"line": 2}], "sourceModified": False}); seq += 1
        points = breakpoint.get("body", {}).get("breakpoints", [])
        if (len(points) != 1 or points[0].get("verified") is not True
                or points[0].get("line") != 2):
            raise DebugProbeError("NOTEBOOK_DEBUG_BREAKPOINT_UNVERIFIED")
        execute_id = client.execute(CODE, allow_stdin=False, stop_on_error=True)
        stopped = _debug_event(client, "stopped")
        thread_id = stopped.get("body", {}).get("threadId")
        if not isinstance(thread_id, int):
            raise DebugProbeError("NOTEBOOK_DEBUG_STOP_THREAD_MISSING")
        stack = _debug_request(client, seq, "stackTrace", {
            "threadId": thread_id, "startFrame": 0, "levels": 20}); seq += 1
        frames = stack.get("body", {}).get("stackFrames", [])
        frame = next((item for item in frames
                      if item.get("source", {}).get("path") == source_path), None)
        if frame is None or frame.get("line") != 2:
            raise DebugProbeError("NOTEBOOK_DEBUG_FRAME_MISSING")
        scopes = _debug_request(client, seq, "scopes", {
            "frameId": frame["id"]}); seq += 1
        local_scope = next((item for item in scopes.get("body", {}).get("scopes", [])
                            if item.get("name", "").lower() in ("locals", "local")), None)
        if local_scope is None:
            raise DebugProbeError("NOTEBOOK_DEBUG_LOCALS_MISSING")
        variables = _debug_request(client, seq, "variables", {
            "variablesReference": local_scope["variablesReference"]}); seq += 1
        marker = next((item for item in variables.get("body", {}).get("variables", [])
                       if item.get("name") == "debug_marker"), None)
        if marker is None or marker.get("value") not in ("41", "41.0"):
            raise DebugProbeError("NOTEBOOK_DEBUG_VARIABLE_MISMATCH")
        _debug_request(client, seq, "continue", {"threadId": thread_id}); seq += 1
        _execute_reply(client, execute_id)
        final = _debug_request(client, seq, "debugInfo"); seq += 1
        if final.get("body", {}).get("isStarted") is not True:
            raise DebugProbeError("NOTEBOOK_DEBUG_FINAL_STATE_INVALID")
        _debug_request(client, seq, "disconnect", {"restart": False,
            "terminateDebuggee": False})
        return {"debugProtocol": "Jupyter-DAP", "breakpointLine": 2,
            "stoppedReason": stopped.get("body", {}).get("reason"),
            "localVariable": "debug_marker", "localValue": "41",
            "continued": True, "executionCompleted": True}
    except queue.Empty as error:
        raise DebugProbeError("NOTEBOOK_DEBUG_TIMEOUT") from error
    finally:
        client.stop_channels()
        manager.shutdown_kernel(now=True)


def main() -> None:
    print(json.dumps(probe(), sort_keys=True))


if __name__ == "__main__":
    main()
