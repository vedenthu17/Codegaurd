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
- `eval/evaluate.py` (binary + per-category P/R/F1, error list, latency p50/p95, `--ablation`, `--json`).
- Minimal UI `codeguard/api/static/index.html`, Dockerfile, docker-compose.yml, `.env.example`.

- Analyzers (`analyzers/`): ai_text, network, paths, secrets, exfil, obfuscation, resources, shell
  (tree-sitter-bash), embedded (string re-scan), fences, sql, deps (top-PyPI typosquats), bandit_layer,
  ai_model (optional ONNX classifier, models/pi, downloaded by scripts/download_model.py).
- Eval: dev 30/30 + 12/12 (tuned on dev, so optimistic), benign_extra 16/16, `eval/mutate.py`
  (structural; 1.00 except rename artifact), `eval/fp_scan.py` (stdlib ~2% blocked, mostly genuine
  dynamic exec), `eval/redcode_eval.py` (untested on real data). Tests: 103 passing; demo 5/5.
- Gotchas: all regexes must be length-bounded (500KB robustness input); time budget (250ms) is shared,
  so heavy loads go in `warm()`; fusion dedupes per (category, lines). When writing files via shell
  heredocs, doubled backslashes can turn into control characters (a `backslash-b` became a backspace) - use
  the Edit tool or chr() for regex escapes.
- `eval/stress.py` = extreme stress (robustness, concurrency, big benign, composites): all green, see README. The request time budget scales with input size; do not shrink it (large files lose layers and verdicts become machine-speed dependent). README.md and docs/WRITEUP.md carry the numbers; update them when analyzers change.

TODO:
- Independently written held-out set (teammate, without seeing the rules), then sweep the 0.5 block
  threshold (fusion.py) on dev + held-out + stdlib scan + RedCode combined.
- Obfuscation robustness is untested; JS is regex-only; shell does not resolve variables.
- Run RedCode-Exec (download it; eval only, never copy patterns, never execute).
- Replace Bandit's per-call manager with direct AST visitors to cut latency.

## Commands
- Tests: `.venv/Scripts/python -m pytest`
- Serve: `.venv/Scripts/python -m uvicorn codeguard.api.app:app --port 8000`
- Demo: `.venv/Scripts/python demo/intercept_check.py [--self-test] [--safe F --unsafe F] [--url U]`
