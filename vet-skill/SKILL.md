---
name: vet-skill
description: "Vet third-party skills before install: static scan + local LLM second opinion."
version: 1.3.0
author: Chad King
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, skills, vetting, scanning, llm]
---

# Vet Skill

Gate every third-party skill install through a two-layer safety check before it
touches the machine: a local static scan (zero LLM calls) plus an independent
review from a local LLM endpoint (exactly one fresh chat).

## When to use

- The user asks to install a skill from the hub, a URL, a repo, or a file
- An unknown/untrusted skill or bundle needs review before it runs
- A skill already present looks suspicious and should be re-checked

## Procedure

1. **Locate the target.** Local path (skill dir or single file) or an http(s) URL.
2. **Run the scanner:**

   ```bash
   python3 <install-dir>/scripts/vet_skill.py <path-or-url> --with-llm
   ```

   `<install-dir>` is the folder the skill was copied into — on a default
   Hermes install that's `~/.hermes/skills/operations/vet-skill`. Add `--json`
   for machine-readable output and `--no-cache` to force a fresh scan (ignore
   the verdict cache). Exit codes: `0` PASS, `1` ERROR (input failed to
   fetch/parse/extract), `2` HOLD, `3` BLOCK. Without `--with-llm`, PASS means
   **static-clean only** — the operator still decides whether a second opinion
   is required.

3. **Act on the verdict:**
   - **PASS** — safe to install. Proceed with the normal install path.
   - **HOLD** — needs the user's explicit approval. Present the flagged findings and the
     LLM reasons; do not install without their go-ahead.
   - **BLOCK** — malicious patterns (exec, curl|bash, persistence, exfil, obfuscation,
     prompt injection). Refuse to install. Show the evidence: rule, file, line, snippet.
4. **For URL targets** the scanner fetches the content itself — confirm what it
   actually downloaded before installing anything it references.

## What the static layer flags

- Code execution: `eval`/`exec`/`compile`, `__import__`, `os.system`, subprocess, `shell=True`
- Download-execute: `curl|bash`, `wget|sh`, fetching executables to disk
- Obfuscation: base64/hex decode chains, `zlib`/`marshal`/`pickle` payloads, `chr()` chains
- Network: raw IP URLs, shorteners (opaque destination), webhook sinks, paste/raw hosts
- Secrets: env reads, Keychain access, credential files, secret-like assignments
- Persistence: crontab/launchd/systemd, shell-profile writes, sudo
- Deception: prompt-injection markers, LLM system-prompt injection (`<<SYS>>`,
  `<|im_start|>`, "override your instructions"), hidden instructions, zero-width
  unicode, social-engineering/trust markers, tool shadowing
- Reverse shells & C2: `/dev/tcp`, `mkfifo`, `nc -e`, `pty.spawn`, PowerShell
  `-EncodedCommand`/`Invoke-Expression`, `certutil -decode`
- Destructive commands: `--no-preserve-root`, `rm -rf /`, `dd`, shutdown/reboot
- Logic bombs: time/date or environment-conditional payloads

Doc files (READMEs, .md) are informational only — their findings are capped at
severity 1 and never gate a verdict by themselves. Only code-level findings (medium+)
and the LLM opinion gate installs.

## The LLM layer

The scanner bundles the skill's content and sends it to an OpenAI-compatible
LLM endpoint (`/v1/chat/completions`) in a **fresh chat** — no shared context —
asking for a structured PASS/HOLD/BLOCK verdict plus reasons. It calls each
configured model in order until one succeeds (up to one call per model); the
next model is tried if a reply is unparsable.

- If the endpoint is unreachable and the static layer is clean, the verdict falls to
  **HOLD** — never auto-PASS without the second opinion.
- Static BLOCK stands regardless of the LLM reply.
- Verdicts are cached by content hash; re-running an identical target is
  instant and tied to the LLM endpoint config. A `--with-llm` run that only
  finds a no-LLM (or failed-bridge) cache entry forces a fresh LLM call.

## Configuration

All settings are environment variables (no config file):

| Variable | Default | Purpose |
|---|---|---|
| `VET_SKILL_LLM_URL` | `http://127.0.0.1:54706/v1/chat/completions` | OpenAI-compatible LLM endpoint for the second opinion |
| `VET_SKILL_LLM_MODELS` | `gemini-3.5-flash-lite,gemini-3.6` | Comma-separated model list (fallback order) |
| `VET_SKILL_LLM_API_KEY` | *(unset)* | Added as `Authorization: Bearer <key>` on LLM calls |
| `VET_SKILL_LLM_TIMEOUT` | `30` | Seconds to wait per LLM call |
| `VET_SKILL_LLM_ALLOW_INSECURE` | *(unset)* | Set to `1` to permit `--with-llm` against a public `http://` endpoint (off by default — skill content must not cross the wire in cleartext to a public host) |
| `VET_SKILL_CACHE_DIR` | `~/.cache/vet-skill` | Verdict cache location (dir created mode 0700, files 0600) |

The default LLM URL points at a localhost port that may not exist on your
machine — that's expected: if the endpoint is unreachable, `--with-llm` returns
**HOLD** by design. The default endpoint is the **Gemini bridge** — a
local-only LLM proxy (part of the AiSupervisor local model stack, serving
Gemini models on port 54706); it exists only if you run that stack. Set
`VET_SKILL_LLM_URL` to your own endpoint otherwise (Ollama, LM Studio, a
local Gemini proxy, or any OpenAI-compatible service — always HTTPS for
remote endpoints), `VET_SKILL_LLM_MODELS` to a model it serves, and
`VET_SKILL_LLM_API_KEY` if it requires one.

## Pitfalls

- Do not skip the scanner for "official-looking" sources — vet everything, including
  hub installs.
- A clean static score is not a pass by itself when the LLM endpoint is down: report HOLD
  and let the user decide.
- Never install a BLOCKed skill in any form, including "just the SKILL.md".
- Keep the bundle size sane: the scanner caps what it sends to the LLM (~24 KB),
  so multi-file skills are reviewed as a summary of their files, not every byte.
- Never send skill content to public/cloud LLMs by default — the default
  endpoint is local. The tool refuses a public `http://` endpoint outright
  (`VET_SKILL_LLM_ALLOW_INSECURE=1` overrides); anything else must be HTTPS.
- If a skill scans as empty (no scannable files) or the archive is malicious
  (path-traversal, symlink, or bomb members), the verdict is HOLD or ERROR —
  never a quiet PASS.

## Verification

- Exit code 0 = PASS, 2 = HOLD, 3 = BLOCK.
- `--json` report includes: verdict, static score, per-finding evidence (rule/file/line/
  snippet), the LLM verdict + reasons, and cache status.
