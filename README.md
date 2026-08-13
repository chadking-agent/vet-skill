# vet-skill

Two-layer safety gate for third-party AI-agent skills: a local static scan
(zero LLM calls) plus an optional independent LLM second opinion — before
anything from the outside touches your machine.

```
python3 vet_skill.py <path-or-url> --with-llm
```

Verdicts: `0` PASS · `1` ERROR · `2` HOLD · `3` BLOCK.

## What it does

**Layer 1 — static scan (always, free):** regex-based heuristics over the
skill's files that flag:

- Code execution: `eval`/`exec`/`compile`, `__import__`, `os.system`, subprocess, `shell=True`
- Download-execute: `curl|bash`, `wget|sh`, fetching executables to disk
- Obfuscation: base64/hex decode chains, `zlib`/`marshal`/`pickle` payloads, `chr()` chains
- Network: raw IP URLs, shorteners, webhook sinks, paste/raw hosts
- Secrets: env reads, Keychain access, credential files
- Persistence: crontab/launchd/systemd, shell-profile writes, sudo
- Deception: prompt-injection markers, hidden instructions, zero-width unicode, tool shadowing
- Logic bombs: time/date or environment-conditional payloads

Doc files (READMEs, `.md`) are informational only — their findings are capped
and never gate a verdict by themselves. Only code-level findings and the LLM
opinion gate installs.

**Layer 2 — LLM second opinion (optional, `--with-llm`):** the scanner bundles
the skill's content (capped ~24 KB) and sends it to an OpenAI-compatible
endpoint in fresh chats — it calls each configured model in order until one
succeeds (up to one call per model) — asking for a structured PASS/HOLD/BLOCK
verdict plus reasons. If the endpoint is unreachable and the static layer is
clean, the verdict falls to **HOLD** — never auto-PASS without the second
opinion. Static BLOCK stands regardless.

## Requirements

- Python 3.9+ — stdlib only, no dependencies, no install step
- Optional: an OpenAI-compatible LLM endpoint for `--with-llm`

## Install

```bash
git clone https://github.com/chadking-agent/vet-skill.git
# for Hermes users: copy the skill folder into your skills directory
cp -r vet-skill/vet-skill ~/.hermes/skills/operations/vet-skill/
# or use the CLI directly from anywhere:
python3 vet-skill/vet-skill/scripts/vet_skill.py <path-or-url>
```

## Usage

```bash
# static scan only
python3 vet_skill.py ~/Downloads/some-skill

# static + LLM second opinion
python3 vet_skill.py https://example.com/skill.zip --with-llm

# machine-readable report
python3 vet_skill.py ~/Downloads/some-skill --with-llm --json
```

| Exit | Meaning |
|---|---|
| `0` | PASS — safe to install. Without `--with-llm`, PASS is **static-clean only**; the operator still decides whether a second opinion is required |
| `1` | ERROR — input failed to fetch/parse (bad URL, missing path, oversized download) |
| `2` | HOLD — needs human review (static findings, or LLM unavailable/ambivalent) |
| `3` | BLOCK — malicious patterns found; do not install |

URL targets are fetched with a 2 MiB cap, basename-sanitized filenames, and
scheme-consistent, redirect-capped handling. Content is hashed and cached by
verdict key, so re-running an identical target is instant.

## LLM configuration (env vars, no config file)

| Variable | Default | Purpose |
|---|---|---|
| `VET_SKILL_LLM_URL` | `http://127.0.0.1:54706/v1/chat/completions` | OpenAI-compatible chat completions endpoint. The default is the **Gemini bridge** — a local-only LLM proxy (AiSupervisor local model stack, Gemini models on port 54706); it exists only if that stack is running |
| `VET_SKILL_LLM_MODELS` | `gemini-3.5-flash-lite,gemini-3.6` | Comma-separated fallback model list |
| `VET_SKILL_LLM_API_KEY` | *(unset)* | Sent as `Authorization: Bearer <key>` |
| `VET_SKILL_LLM_TIMEOUT` | `30` | Seconds per LLM call |
| `VET_SKILL_CACHE_DIR` | `~/.cache/vet-skill` | Verdict cache directory |

Example against a public provider:

```bash
VET_SKILL_LLM_URL="https://api.openai.com/v1/chat/completions" \
VET_SKILL_LLM_MODELS="gpt-4o-mini" \
VET_SKILL_LLM_API_KEY="sk-..." \
python3 vet_skill.py ./suspect-skill --with-llm
```

## Watch-outs

- **Content is sent to whatever `VET_SKILL_LLM_URL` points at — verbatim.**
  The default is localhost-only by design. Never point it at a public/cloud
  endpoint if the skill under review is confidential, and always use HTTPS
  for remote endpoints.
- Vet everything, including "official-looking" sources. Never install a
  BLOCKed skill in any form.
- The static scan is heuristic, not a malware sandbox — manually review
  HOLDs.
- Cache stores scan content in plaintext; point `VET_SKILL_CACHE_DIR` at a
  location you don't mind persisting.
- Multi-file skills are sent to the LLM as a per-file summary (~24 KB cap),
  not every byte.

## License

MIT — see [LICENSE](LICENSE). This is an independent implementation, written
for the Hermes agent ecosystem. Changelog: [CHANGELOG.md](CHANGELOG.md).

- **Self-scan:** running vet-skill on its own repo skips the script itself — its detection patterns are literal strings in the source, so it cannot vet itself. Scanning your own copy returns PASS (with the expected doc-level findings).
