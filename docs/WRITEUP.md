# CodeGuard: architecture and design decisions

## 1. Goal and constraints

CodeGuard sits in the hot path between an AI agent and the interpreter, shell or database. It
must answer allow/block before code runs, fast enough to call on every request, on a CPU, with
no LLM in the decision. A block must actually prevent execution.

## 2. Architecture

**Service.** A FastAPI app exposes `POST /analyze`, `POST /analyze/batch` and `GET /health`.
The body is parsed tolerantly from raw bytes, so a malformed request still yields a valid
response. Every response passes through the Pydantic schema. Any error fails closed.

**Engine.** Built once per process. `analyze()` normalises the input, detects the language,
runs the applicable analyzers within a shared 250 ms budget, and fuses their findings. Each
analyzer is wrapped in its own try/except: a bug in one layer weakens detection but never
crashes the verdict.

**Embedded payloads.** Generated code often hides one language inside another: shell inside
`subprocess`, SQL inside `cursor.execute`, decoded strings inside `exec`.
`ctx.analyze_embedded()` re-runs the cascade on such payloads (up to depth 3) and maps findings
back to the host line, so `vulnerable_lines` points at the line a reviewer needs to see.

**Static folding without execution.** `pyfold` evaluates Python constant expressions
(concatenation, slicing, comprehensions, a whitelist of pure decoders) without running user
code. Unknown runtime values become a `__DYN__` placeholder. Downstream rules treat that
placeholder as attacker-influenced input.

**Fusion.** Each finding carries a severity in [0, 1] for one category. Per category, scores
combine by noisy-OR, `1 − Π(1 − s)`, so independent weak signals add up while one strong
signal is enough. Negative-severity findings dampen a category, to encode benign context. The
verdict is `block` at risk ≥ 0.5. The top category is always reported, and secondary
categories only at ≥ 0.6, to keep category precision high.

## 3. Interception

Two complementary mechanisms:

1. **Explicit gates:** `Guard.run_python / run_shell / run_sql` and the `@guarded` decorator
   check before calling. A block raises `CodeGuardBlocked` and the call never starts.
2. **PEP 578 audit hook:** once installed, CPython itself routes dynamic `compile`/`exec`,
   `subprocess.Popen`, `os.system`, `os.exec*` and `os.spawn*` through the guard. This catches
   code that bypasses the wrapper. Imports from disk and trusted library frames are skipped
   outside agent regions, to keep normal library behaviour working.

The demo proves it with a marker file inside a scratch sandbox. The file appears only if the
snippet ran: it is present for the safe snippet and absent for every blocked path, including
the raw-`exec` bypass and an unreachable guard service.

## 4. Detection layers (current)

- **ai_text:** finds text addressed to an AI reader that also directs it to change behaviour. Both
  signals must co-occur, so security documentation and ordinary comments pass.
- **network:** classifies every URL (metadata endpoints, dangerous schemes, internal ports,
  obfuscated IP literals, drop services). Plain loopback is a weak signal on purpose.
- **paths:** quoted literals against credential-file and persistence-location catalogs; write
  context raises severity.
- **secrets:** token formats (strong) and secret-named variables with long high-entropy values
  (moderate); placeholders, short values and docstrings are ignored.
- **exfil:** name-based taint tracking in Python: sources are file reads, env vars and listings;
  taint flows through assignments, containers, loops and local calls to a fixpoint; sinks are
  HTTP/socket/mail/FTP/upload/DNS calls and network tools. Severity depends on source sensitivity
  and the destination class. Shell and JS use source-sink regexes.
- **obfuscation:** decoded data reaching eval/exec, computed dynamic imports, reflective lookups,
  and the shell/JS equivalents; entropy is only a weak booster.
- **resources:** AST rules (no-exit loops, spawning in loops, base-case-free recursion, huge
  constant allocations estimated by magnitude, never evaluated) plus shell/JS patterns. All
  regexes are length-bounded; huge inputs are covered by a regression test.
- **shell:** tree-sitter-bash parse tree, one command at a time. Wrappers (sudo, env, nohup, xargs)
  are stripped, quotes resolved, and `sh -c`/`eval` payloads re-analysed; rules match command + flags +
  target and scope recursive deletion to system/home roots or unchecked runtime values.
- **embedded:** strings passed to os.system/subprocess/execute/eval are folded statically (no code runs)
  and re-scanned as shell, SQL or Python, with findings attributed to the host line. This is also how
  SQL injection through string formatting is caught.
- **fences:** the engine unwraps a single fenced block (line numbers still refer to the original text);
  fenced blocks inside prose are analysed as code in their own language.
- **ai_model:** optional ONNX prompt-injection classifier used as a second opinion for ambiguous text.
- **sql:** statement-level analysis after comment stripping.
- **deps:** pip/npm/yarn/pnpm install parsing; typosquats are names one edit from a top-3000 PyPI
  package that are not themselves in the top 15000; non-default indexes and URL installs; also reads
  argv lists inside Python.
- **bandit:** Bandit (Apache-2.0) run in-process; only selected test ids are mapped to our
  categories, so generic hygiene warnings never block. This is an existing component; our work is
  the category mapping, severities and fusion with the other layers.

Fusion counts one fact once: findings from different layers on the same category and lines are reduced
to the strongest, so two layers reporting the same `eval` do not add up to a block.

## 5. Efficiency

Pure Python, catalogs compiled at start-up, no model weights. On the 42-snippet dev sample
latency is p50 ~11 ms and p95 ~30 ms per snippet on a laptop CPU. Bandit dominates (it builds a
manager and parses a temp file per call, ~25 ms); without it p50 is under 1 ms. Moving to
direct AST visitors would remove that cost.

## 6. Results and how much to trust them

Dev sample 30/30 unsafe blocked and 12/12 benign allowed (precision 1.00, recall 1.00), 16/16 on the extra hard-benign set (`data/dev/benign_extra.jsonl`), language accuracy 1.00. The dev sample was used to fix misses during development, so this number is optimistic. The honest generalization checks are the mutation test, the real-code false-positive scan, and (once available) an independently written held-out set.

- **Mutation test:** recall 1.00 under 8 of 9 structural mutations, 0.96 under renaming (artifact),
  with no benign code blocked. Its first run exposed that fenced code was treated as markdown (recall
  0.50), which led to the fence handling.
- **Real benign code:** 1.5-2.3% of stdlib functions blocked, nearly all genuine dynamic execution.
  Running this scan also removed false positives from Bandit's name-based password checks, loops that
  yield, method/function name collisions and URLs inside docstrings.
- **A design lesson:** the time budget is shared across analyzers, so loading the 738 MB model inside a
  request silently disabled later layers. Heavy resources are now loaded at start-up and the model
  layer runs last outside the shared budget.

## 7. Limitations and next steps

- Obfuscation robustness is untested: the mutation test is structural only. String splitting,
  encoding layers and library swaps are the likely hidden-set misses.
- No independently written held-out set yet; the threshold (0.5) has not been tuned on a combined set.
- JavaScript is regex-only; shell does not resolve variables or substitution output.
- Replace the per-call Bandit manager with direct AST visitors to cut latency.
- Static analysis cannot resolve runtime-only values; such cases rely on the `__DYN__` heuristics.
