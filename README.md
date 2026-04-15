# PolicyMesh

PolicyMesh is a FastAPI-based runtime security control plane for AI agents that evaluates tool-call requests, scores risk, and enforces policy before execution.

## Features

- Runtime evaluation of agent actions
- Prompt-injection signal detection
- Sensitive data and exfiltration risk scoring
- API key protection for evaluation endpoint
- Audit logging to JSONL
- Interactive FastAPI docs

## Run locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
