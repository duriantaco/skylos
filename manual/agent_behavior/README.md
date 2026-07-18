# Manual Agent Behavior Smoke Test

Terminal 1:

```bash
.venv/bin/python manual/agent_behavior/fake_server.py
```

Terminal 2:

```bash
skylos agent test manual/agent_behavior/agent-test.yml \
  --allow-contract-endpoint --no-artifacts
```

The fake endpoint returns standard Chat Completions messages with explicit
finish reasons, tool calls, refusal, and source evidence. The expected result
is `pass` with ten deterministic assertions across three scenarios. Tool
selection and the final answer with explicit source-ID evidence are separate
turns because Skylos observes returned tool calls but does not execute them.
