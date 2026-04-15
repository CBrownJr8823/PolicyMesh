# PolicyMesh

PolicyMesh is a FastAPI-based runtime security control plane for AI agents that evaluates tool-call requests, scores risk, and enforces policy before execution.

## Features

- JWT-based authentication
- Runtime evaluation of agent actions
- Prompt-injection signal detection
- Sensitive data and exfiltration risk scoring
- In-memory rate limiting
- Audit logging to JSONL
- Health and readiness endpoints
- Docker support
- Pytest coverage

## Local setup

```bash
cp .env.example .env
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:
- http://127.0.0.1:8000/docs

## Auth

Use:
- username: `admin`
- password: `AdminPass123!`

First call `POST /auth/token`, then use the returned bearer token in `Authorize` for protected requests.

## Endpoints

- `GET /health`
- `GET /ready`
- `POST /auth/token`
- `POST /evaluate`

## Run tests

```bash
pytest
```

## Run with Docker

```bash
docker compose up --build
```
