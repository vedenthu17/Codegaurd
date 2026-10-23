# CodeGuard — project context

Hackathon project: real-time pre-execution safety layer for LLM-generated code.
Full brief: `../CodeGuard_Hackathon_Problem_Statement.docx`. Dev sample: `data/dev/codeguard_dev.jsonl`.

## Hard requirements
- Request `{"code": "..."}` → response with required `verdict` (allow|block), `risk_score` (0-1),
  `categories` (list), `code_language`; optional `reason`, `vulnerable_lines`.
- Nine categories: secret_access, data_exfiltration, destructive_command, persistence_or_privesc,
  obfuscated_execution, dependency_risk, resource_exhaustion, ssrf_network_exfil, ai_targeted_instructions.
- No LLM-as-judge, CPU only, Python 3.10+, no external API keys. Never execute test snippets
  (only the organizer's safe/unsafe demo pair). No hard-coding dev answers.

## Dev sample format
JSONL rows: `id, code, language, category, label, rationale`. `category` is "benign" or
comma-separated names; `label` 0/1. Languages seen: python, bash, sql, javascript, yaml, markdown.

## Status
Done:
- `codeguard/api/` FastAPI: POST /analyze, POST / (alias), POST /analyze/batch, GET /health.
  Raw-body parsing; always HTTP 200 + schema-valid body; errors fail closed.
- `codeguard/engine.py` cascade orchestrator (per-analyzer isolation, time budget,
  `Engine(disabled={...})` for ablation, `ctx.analyze_embedded(...)` for payloads inside strings).
- `codeguard/fusion.py` noisy-OR scoring, threshold 0.5, primary + strong secondary categories.
- `codeguard/langdetect.py` (42/42 on dev).
- `codeguard/guard/` Guard (decorator, run_python/run_shell/run_sql), PEP 578 audit hook,
  Local/Http checkers that fail closed.
- `demo/intercept_check.py` — 5 scenarios, passes with `--self-test` (stub detector).
- Helpers: `analyzers/pyfold.py` (non-executing constant folder), `analyzers/netutil.py`,
  `analyzers/common.py`, `rules/catalog.py`.
- Tests: 47 passing (`.venv/Scripts/python -m pytest`).

TODO:
- Detection analyzers (registry in `codeguard/analyzers/__init__.py::build_all`; interface:
  `name`, `languages` (frozenset or None), `run(ctx) -> Iterable[Finding]` via `ctx.finding(...)`).
- `eval/evaluate.py` (binary + per-category P/R/F1, FPs, latency p50/p95, per-analyzer ablation).
- Minimal UI at `codeguard/api/static/index.html`, Dockerfile, docker-compose, `.env.example`,
  README (architecture, components + licenses, assumptions, limitations, AI-assistant disclosure),
  `docs/WRITEUP.md`.

## Commands
- Tests: `.venv/Scripts/python -m pytest`
- Serve: `.venv/Scripts/python -m uvicorn codeguard.api.app:app --port 8000`
- Demo: `.venv/Scripts/python demo/intercept_check.py [--self-test] [--safe F --unsafe F] [--url U]`
