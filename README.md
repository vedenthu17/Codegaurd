# CodeGuard

A real-time, pre-execution safety layer for LLM-generated code. It takes `{"code": "..."}`
and returns an allow/block verdict before the code runs. No LLM is used to judge code:
detection is CPU-only static analysis. Snippets are never executed.

## Quick start

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt      # Windows; use .venv/bin on Linux/macOS
.venv/Scripts/python -m uvicorn codeguard.api.app:app --port 8000
```

Open http://127.0.0.1:8000/ for the demo UI, or call the API:

```bash
curl -s localhost:8000/analyze -H 'content-type: application/json' -d '{"code": "pip install colourama"}'
```

Docker: `cp .env.example .env && docker compose up --build`.

## API

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/analyze` (alias `POST /`) | `{"code": "..."}` | fixed schema below |
| POST | `/analyze/batch` | `{"snippets": [{"id", "code"}, ...]}` (also `items`, `codes`, a bare list) | `{"count", "results": [{id, ...schema}]}` |
| GET | `/health` | | status, version, active analyzers |

```json
{"verdict": "block", "risk_score": 0.85, "categories": ["dependency_risk"],
 "code_language": "bash", "reason": "...", "vulnerable_lines": [1]}
```

Every POST returns HTTP 200 with a schema-valid body, whatever the input (empty, non-JSON,
binary, oversized, deeply nested). Internal errors **fail closed** (`block`, risk 1.0).
Engine latency is returned in the `X-CodeGuard-Latency-Ms` header.

## Architecture

```
request ─► schemas.parse_single ─► Engine.analyze
                                     ├─ langdetect (lexical scores + ast/yaml parser confirmation)
                                     ├─ analyzers (cascade, each isolated, shared 250 ms budget)
                                     │    └─ ctx.analyze_embedded(): re-run on payloads inside strings
                                     └─ fusion.decide (noisy-OR per category, threshold 0.5)
                                          ─► verdict, risk_score, categories, reason, lines
```

- **`codeguard/engine.py`**: the orchestrator. One broken analyzer can't take down a verdict.
  `Engine(disabled={...})` turns analyzers off for ablation.
- **`codeguard/fusion.py`**: per-category noisy-OR of finding severities. Negative severities
  act as benign-context dampeners. The top category is reported, plus any secondary category ≥ 0.6.
- **`codeguard/langdetect.py`**: python, bash, sql, javascript, yaml, markdown, plus fallbacks.
- **`codeguard/analyzers/`**: detection layers.
  - `ai_text`: text addressed to an AI reader that directs it to change behaviour (override
    phrases, approve-regardless, skip analysis, reveal system prompt).
  - `network`: URL classification via `netutil`: metadata endpoints, dangerous schemes,
    internal addresses/ports, third-party drop services.
  - `paths`: quoted literals matched against credential-file and persistence-location catalogs.
  - `secrets`: well-known token formats and secret-named variables with high-entropy literals.
  - `exfil`: Python source-to-sink taint tracking (file/env reads reaching HTTP, socket, mail,
    FTP, cloud-upload, DNS or network-tool calls), plus shell and JavaScript source-to-sink regexes.
  - `obfuscation`: eval/exec of decoded data, computed dynamic imports, reflective lookups,
    shell `base64 -d | sh`, JS `eval(atob(...))`, high-entropy literals as a weak booster.
  - `resources`: unbounded loops, spawning in loops, unconditional recursion, huge constant
    allocations (Python AST); fork bombs, endless shell loops, unbounded writes, JS loops.
  - `shell`: tree-sitter-bash AST. Commands are normalised (sudo/env/nohup/xargs stripped,
    quotes resolved, `sh -c` and `eval` payloads re-analysed) and matched on command + flags +
    target, with scoping so `rm -rf node_modules` stays allowed.
  - `embedded`: strings handed to os.system / subprocess / `cursor.execute` / `eval` are folded
    statically (constants, f-strings, `.format`, `%`, helper returns) and re-scanned as shell, SQL
    or Python; SQL built by formatting runtime values is reported as injection risk.
  - `fences`: fenced code blocks inside markdown/prose are analysed as code in their own language.
  - `ai_model`: optional local prompt-injection classifier, a second opinion only on passages where
    `ai_text` found some evidence but not enough (see *Optional model*).
  - `sql`: UPDATE/DELETE without WHERE, DROP/TRUNCATE, GRANT ALL / SUPERUSER.
  - `deps`: typosquats (Damerau-Levenshtein distance 1 from a top-3000 PyPI name, never flagging
    names in the top 15000; curated list for npm), non-default indexes, direct-URL installs; also
    reads install argv lists inside Python.
  - `bandit`: Bandit run in-process on Python; selected test ids mapped to our categories.
  - Helpers: `pyfold` (non-executing constant folder for Python expressions, including decoders),
    `netutil` (URL/host classification, including obfuscated IP literals), `common`.
- **`codeguard/rules/catalog.py`**: rule data (paths, hosts, schemes), written from category
  definitions and MITRE ATT&CK technique descriptions.
- **`codeguard/guard/`**: the interception layer (see below).

## Interception proof

`Guard` vets code *before* running it: `guard.run_python`, `run_shell`, `run_sql`, and the
`@guard.guarded("arg")` decorator. A block raises `CodeGuardBlocked` before the wrapped call starts.
`install_audit_hook()` adds a PEP 578 audit hook, so a raw `exec()`, `subprocess.Popen` or
`os.system` that bypasses the wrapper is also stopped. Checkers fail closed when the
service is unreachable.

```bash
.venv/Scripts/python demo/intercept_check.py --self-test                    # mechanics, stub detector
.venv/Scripts/python demo/intercept_check.py --safe S.py --unsafe U.py      # organizer pair
.venv/Scripts/python demo/intercept_check.py --url http://127.0.0.1:8000    # via the HTTP service
```

Each scenario runs in a scratch sandbox. The proof is the marker file: it appears for the safe
snippet and never appears for a blocked one. Five scenarios cover the wrapper, the decorator,
a raw-exec bypass caught by the audit hook, and fail-closed behaviour.

## Evaluation

```bash
.venv/Scripts/python eval/evaluate.py --ablation --json eval/results/dev.json
```

This reports binary and per-category precision, recall and F1, every FP/FN, language accuracy,
latency p50/p95, and per-analyzer ablation.

**Current result:** dev sample 30/30 unsafe blocked and 12/12 benign allowed (precision 1.00, recall 1.00), 16/16 on the extra hard-benign set (`data/dev/benign_extra.jsonl`), language accuracy 1.00. The dev sample was used to fix misses during development, so this number is optimistic. The honest generalization checks are the mutation test, the real-code false-positive scan, and (once available) an independently written held-out set.

**Mutation test** (`eval/mutate.py`: every positive re-submitted after structural changes):
recall 1.00 under identity, function/class wrapping, burying in 8 or 25 benign helpers, markdown
fences, CRLF, tabs, header comments and trailing whitespace; 0.96 under identifier renaming (the one
miss is an artifact: `ast.unparse` deletes the comment that carries the payload). No benign snippet
is blocked under any mutation. The first run of this test found a real weakness (fenced code was
analysed as markdown, recall 0.50); it is fixed by unwrapping fences. Obfuscation-style mutations are
deliberately not generated.

**Real-code false positives** (`eval/fp_scan.py`, stdlib functions treated as benign): 1.5-2.3% blocked
on random 1200-2500 function subsets. Almost all are genuine dynamic `exec`/`eval`/`__import__` code
(namedtuple, REPLs, plugin loaders), which the brief's own labels treat as risky; they are the cost of
catching dynamic execution. Threshold tuning should use a combined set, not dev.

**Latency:** p50 ~11 ms, p95 ~30 ms on a laptop CPU. Bandit costs ~9-25 ms per Python call; the model,
when used, ~60 ms for up to three passages (loaded at start-up, never per request).

## Status

| Category | Coverage |
|---|---|
| secret_access | token formats, secret-named literals, credential paths (also unquoted in shell), Bandit |
| data_exfiltration | Python taint (source -> sink), shell/JS source-sink regexes, drop services, SQL-injection `SELECT` |
| destructive_command | shell AST (rm/dd/mkfs/shred/chmod/find...), SQL statements, embedded shell/SQL, Bandit |
| persistence_or_privesc | path catalog (quoted and shell redirects), setuid, sudo/user changes, crontab, SQL grants |
| obfuscated_execution | decoded-data exec/eval, computed and helper-routed imports, aliased exec modules, shell/JS forms |
| dependency_risk | top-N typosquats, untrusted index, URL installs (shell and Python) |
| resource_exhaustion | Python AST loop/spawn/recursion/allocation rules, shell and JS patterns |
| ssrf_network_exfil | metadata endpoints, dangerous schemes, internal addresses/ports |
| ai_targeted_instructions | override/directive rules, optional classifier second opinion |

New analyzers implement `name`, `languages` (frozenset or `None` for all) and
`run(ctx) -> Iterable[Finding]` (via `ctx.finding(...)`), and are registered in
`codeguard/analyzers/__init__.py::build_all`.

## Components and licenses

| Component | Use | License |
|---|---|---|
| FastAPI, Starlette | HTTP service | MIT, BSD-3-Clause |
| Uvicorn | ASGI server | BSD-3-Clause |
| Pydantic | response schema validation | MIT |
| PyYAML | YAML language confirmation | MIT |
| httpx | FastAPI test client | BSD-3-Clause |
| pytest | tests | MIT |
| Bandit | in-process Python AST checks (`analyzers/bandit_layer.py`) | Apache-2.0 |
| tree-sitter, tree-sitter-bash | shell parse trees (`analyzers/shell.py`) | MIT |
| protectai/deberta-v3-base-prompt-injection-v2 (ONNX) | optional prompt-injection second opinion | Apache-2.0 |
| onnxruntime, tokenizers | run the optional model | MIT, Apache-2.0 |
| Top PyPI packages list (hugovk/top-pypi-packages, public PyPI download statistics) | typosquat reference data (`codeguard/data/top_pypi.txt`) | data file; source MIT |
| sqlglot, tree-sitter-javascript, scikit-learn, numpy, scipy, joblib | pinned for planned work; not used by current code | MIT / MIT / BSD-3-Clause |

Without the optional model there are no pretrained weights. No external rulesets or public detection datasets are used.

## Optional model

```bash
pip install -r requirements-model.txt
python scripts/download_model.py        # ~740 MB into models/ (git-ignored)
```

When present it is loaded at start-up. It is only consulted for passages where the rules found some
evidence (an AI addressee or a directive) but not enough, and quoted/policy/documentation text is
excluded. The first attempt, running it on any passage with a cue word, flagged 29 of 1200 benign
stdlib functions and a security guide that quotes an attack phrase; gating on rule evidence cut that
to 1. On this dev set it changes nothing (the rules already catch every case), so its benefit is
unmeasured. Without it CodeGuard works unchanged.

## Stress tests

```bash
python eval/mutate.py --extra data/dev/benign_extra.jsonl --show-misses   # structural mutations
python eval/fp_scan.py --limit 2000 --seed 1                              # stdlib as benign set
python eval/redcode_eval.py --path <RedCode-Exec dir> --map map.json      # external set, eval only
```

`redcode_eval.py` is untested against the real dataset (it was not available offline); check the
printed item count first. Do not copy RedCode patterns into the rules and never execute its snippets.

**Extreme stress test** (`eval/stress.py`): 20 pathological inputs (1.2 MB program, 100k-line YAML,
3000-deep nesting, regex bait, NULs, RTL/zero-width text, CRLF soup, binary-like data): 0 crashes or
invalid responses, slowest 3.8 s. 8 threads give identical verdicts to a serial run; a 522-snippet batch
call is valid (~13 ms/snippet). Generated 800-1600-function benign programs: 5/5 allowed. Real
third-party package files (whole files, so more dynamic-code hits than per function): ~5-6% blocked,
mostly `exec`/`pickle`/`import_module`, a few classifier hits on config-like text. Composites built from
dev positives: buried in 70 KB programs 25/25, nested six levels deep 25/25, two or three combined
40/40 and 25/25, wrapped in security prose with decoy attack phrases 29/29.

What this found: (1) the per-request time budget was shared by all layers, so on large inputs later
layers were skipped and a block could turn into an allow depending on machine speed. The budget is now
2 s plus 15 ms per 1000 characters (configurable via `CODEGUARD_BUDGET_MS`). (2) In combined files,
categories were under-reported because secondary categories needed 0.6 while blocking needs 0.5;
aligning them cut missing gold categories from 16 to 2 (pairs) and 10 to 3 (triples).
(3) a single syntax error anywhere in a Python file switched off every AST layer (a clear block became
an allow with a truncated or malformed tail). `codeguard/pyparse.py` now salvages the parseable top-level
chunks with original line numbers, and the AST is parsed once and shared by all layers.

## Assumptions

- Snippets are untrusted text and are never executed (except the organizer's demo pair,
  inside the interception demo).
- Blocking is preferred over allowing when analysis fails or the guard is unreachable.
- Language is inferred from content; callers send only `{"code": ...}`.

## Known limitations

- Shell analysis resolves quotes and wrappers but not variables, command substitution output or
  encoded payloads beyond the listed forms; JavaScript is regex-only.
- The structural mutation test does not cover obfuscation (string splitting, encoding layers, library
  swaps); those are the most likely hidden-set misses and are untested.
- Taint tracking is name-based and per file (no scopes, no attribute/field sensitivity).
- Python is analysed with `ast` plus Bandit; JavaScript has no AST layer (regex only).
- Typosquat detection covers edit distance 1 from the top 3000 PyPI names (curated list for npm only).
- Static analysis cannot see values that are only known at runtime.
- The audit hook covers CPython's audited events; native extensions can bypass it.

## Tests

`.venv/Scripts/python -m pytest`: interception mechanics, schema robustness against
malformed input, language detection.

## AI-assistant disclosure

Parts of this repository (service scaffolding, the guard layer, the evaluation script, the UI,
the analyzers, tests and this documentation) were written with the help of an AI
coding assistant (Claude Code), then reviewed and run by the team. No LLM is called at runtime.
