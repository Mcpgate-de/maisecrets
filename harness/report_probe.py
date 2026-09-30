"""Each step of the report proof for a dumped UserPromptSubmit payload, by the plugin under test. Prints names and
booleans, never a value. The dump masks values, so the step that compares the result with the subagent's last
answer is left out; the others are what differs between machines (a link or a file, a path, a label, a store).

    python3 harness/report_probe.py <repo root> <dump file>     (MAISECRETS_HOME of the scenario)
"""
import json
import os
import re
import sys

sys.path.insert(0, sys.argv[1])
from maisecrets import detect, hooks  # noqa: E402
from maisecrets.vault import Vault, load_config  # noqa: E402

payload = json.load(open(sys.argv[2], encoding="utf-8"))
prompt, transcript = payload["prompt"], payload["transcript_path"]
body = re.search(r"<task-notification>\n(.*?)\n</task-notification>", prompt, re.S).group(1)
out = hooks._notification_tag(body, "output-file") or ""
subagents = os.path.realpath(transcript[: -len(".jsonl")]) + os.sep + "subagents" + os.sep
task_id = hooks._notification_tag(body, "task-id") or ""
rest = re.sub(r"<result>.*</result>", "<result></result>", prompt, flags=re.S)
print(json.dumps({
    "status": hooks._notification_tag(body, "status"),
    "real_in_subagents": os.path.realpath(out).startswith(subagents),
    "task_file": os.path.isfile(subagents + f"agent-{task_id}.jsonl"),
    "agent_call": hooks._called_an_agent(transcript, hooks._notification_tag(body, "tool-use-id") or ""),
    "rest_hits": [m.kind for m in detect.scan(rest)],
    "rest_stored": len(hooks._inserted_values(rest, Vault(load_config()))),
    "blocks": prompt.count("<task-notification>"), "closes": prompt.count("</task-notification>"),
}))
