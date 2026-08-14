## [1.3.1] — 2026-08-14

- DDD round (fresh-context adversarial review, 10/14 findings applied, exploits
  re-verified closed):
  - **SSRF: initial URL target host is now vetted** — private/loopback/reserved
    hosts refused before the first connect (was: only redirects were guarded)
  - **Silent scan truncation fixed** — hitting the 200-file cap now emits a
    severity-2 finding → HOLD (a payload sorted after 200 benign files used to PASS)
  - **Doc severity capping no longer downgrades malware** — exec-class patterns
    (os.system, curl|bash, reverse shells, persistence) keep their severity in
    README/SKILL.md; only informational doc findings are capped at 1
  - **Endpoint probe is a real HTTP POST now** — a bare TCP listener no longer
    satisfies liveness, so cached LLM PASSes can't replay against a dead endpoint
  - **NUL/binary executable files flagged** — NUL-padded .py/.sh payloads emit a
    finding → HOLD instead of a silent skip
  - **Dotfiles with executable extensions are scanned** — `.evil.sh` no longer
    passes unseen (and the .env credential rule can fire again)
  - Relative redirects resolved via urljoin before vetting (GitHub/CDN-style
    `Location: /path` no longer hard-fails the fetch)
  - LLM `content` arrays normalized (valid OpenAI format no longer → HOLD forever)
  - LLM POST routed through the safe redirect handler
  - `_extract_json_object` rewritten with `raw_decode` (braces inside string
    values can no longer skew extraction)
  - Dynamic-`Function` rule tightened to require a string argument (JS IIFEs no
    longer false-positive)
# Changelog

All notable changes to vet-skill.

## [1.3.0] — 2026-08-14

- Security-hardening + robustness round:
  - **LLM prompt-injection defense:** the skill bundle is now framed as
    untrusted data between explicit markers, the model is instructed to ignore
    any instructions inside the content and to report manipulation attempts in
    `suspicious` — skill content can no longer hijack the reviewer.
  - **New static rules:** LLM system-prompt injection markers (`<<SYS>>`,
    `<|im_start|>`, `[system]`, instruction overrides), reverse/bind shells
    (`/dev/tcp`, `mkfifo`, `nc -e`, `pty.spawn`), PowerShell
    `-EncodedCommand`/`Invoke-Expression`, `certutil -decode`, base64-piped
    download-execute, destructive commands (`--no-preserve-root`, `rm -rf /`,
    `dd`, shutdown/reboot/mkfs), well-known secret env names, social-engineering
    trust markers, dynamic `Function()`.
  - **Cleartext-exfiltration guard:** `--with-llm` refuses a public `http://`
    endpoint (loopback/private HTTP still allowed) unless
    `VET_SKILL_LLM_ALLOW_INSECURE=1` is set.
  - **Archive hardening:** zip members are now checked for drive-letter
    escapes and symlink entries and extracted member-by-member (never through
    `extractall`); tar members additionally reject device files; both formats
    enforce a 50 MiB extracted-content cap and 2000-member cap (bomb guard)
    plus a resolved-path containment check. Extension-less archives are
    detected by magic bytes.
  - **Symlink hygiene:** recursive scan/hash/bundle walks skip symlinks so a
    skill can't pull in content from outside the target tree.
  - **Fail-closed:** a target that yields zero scannable files is HOLD, not a
    silent PASS.
  - **Robust LLM parsing:** balanced-brace JSON extraction (nested objects,
    prose, fences), response size-truncation detection, and coerce/cap of
    `reasons`/`suspicious`.
  - **Cache hygiene:** cache dir created mode 0700, cache files mode 0600;
    `--no-cache` flag forces a fresh scan. Cache-hit reporting now truthfully
    marks a dead-endpoint replay as not-LLM-reviewed.
  - **Bug fixes:** archive extraction failures now produce a clean ERROR exit
    (previously an unhandled traceback that leaked the temp dir); `--version`
    flag added; URL fetches send a User-Agent.

## [1.1.0] — 2026-08-13

- Public-release hardening:
  - Path-traversal fix: URL-target filenames are basename-sanitized before
    writing to the temp dir (a crafted URL could previously write outside it)
  - Download cap: URL targets are fetched with a 2 MiB limit (memory-exhaustion guard)
  - Redirect guard: scheme-consistent, redirect-capped URL fetching
  - LLM config via env vars: `VET_SKILL_LLM_URL`, `VET_SKILL_LLM_MODELS`,
    `VET_SKILL_LLM_API_KEY`, `VET_SKILL_LLM_TIMEOUT`, `VET_SKILL_CACHE_DIR`
  - Bearer auth support for API-key LLM endpoints
  - Exit code `1` documented (input fetch/parse error)
  - Static-only PASS contract documented explicitly
  - Generalization: no personal names, paths, or machine-specific settings
- Three independent model reviews + Gemini verification before release

## [1.0.0] — 2026-08-13

- Initial release: static scanner + optional LLM second opinion for vetting
  third-party AI-agent skills before install. Stdlib-only Python 3.9+.
- Language-aware rule engine (Python/JS/Shell), doc-only findings capped,
  verdicts cached by content hash.

## [1.1.1] — 2026-08-13

- Self-scan fix: vet-skill now skips its own script when scanning (detection
  patterns are literal strings in the source, so self-scanning flagged its own
  rule definitions). A scanner cannot vet itself — documented.

## [1.1.2] — 2026-08-13

- Bug-hunt round (fresh-context review, all six verified live):
  - URL targets now derive the filename from the URL path (query strings and
    dotfiles can no longer slip past the scan — a hostile URL could previously
    make malicious content PASS)
  - Downloaded files are scanned as single-file targets (same branch as local
    files), so no dotfile/suffix filtering is applied
  - Empty `VET_SKILL_LLM_MODELS` no longer crashes at import
  - Non-numeric `VET_SKILL_LLM_TIMEOUT` no longer crashes at import
  - Off-by-one fixed: exactly-2 MiB downloads are accepted, only larger are rejected
  - Redirect handler now allows http→https upgrades (blocked them before);
    still refuses downgrades and non-http(s) targets
  - Temp directories are cleaned up on failed URL fetches (no more leaks)

## [1.1.3] — 2026-08-13

- Security hardening pass (STRIDE threat model):
  - Redirect guard now refuses redirects into loopback/private address space
    (localhost, 127.x, 10.x, 192.168.x, 169.254.x, 172.16-31.x, IPv6 literals)
    — a hostile URL target can no longer aim the fetch at internal services
  - LLM response reads are capped at 1 MiB (unbounded read fixed)

## [1.2.0] — 2026-08-13

- Doubt-driven-development round (fresh-context adversarial review, 15/15
  findings applied):
  - Cache now binds to the LLM endpoint config (URL/models/key fingerprint)
    and expires after 24h; cached PASS only replays if the original run had a
    live LLM review — no more fail-open replay with a dead endpoint, no more
    stuck-HOLD from a failed bridge
  - No silent scan gaps: all non-binary files are scanned (extensionless
    included, binary sniffed); oversized and unreadable files now produce a
    HOLD-gating finding instead of being silently dropped
  - YAML/TOML/JSON/INI/CFG moved from doc-classification to code-classification
    (executable config formats now gate verdicts)
  - zip/tar/tgz targets are extracted and scanned (archive handling); unsafe
    archive members (absolute paths, .., links) are rejected
  - Bounded file reads everywhere (no more full-file materialization in
    hashing/bundling — no OOM on multi-GB files)
  - Self-scan skip is content-based, so copies of the script no longer false-BLOCK
  - Redirect guard resolves DNS and blocks any private/loopback/reserved
    address, including alternate encodings
  - LLM call semantics documented accurately (up to one call per configured
    model)
  - Markdown table backtick fixes, LICENSE corrected, stale QA artifact removed

## [1.2.1] — 2026-08-13

- Cross-model (Gemini) adversarial review round:
  - Cache-hit verdicts are re-derived from stored evidence, never trusted verbatim
  - `--with-llm` cache hits probe endpoint reachability first; a down endpoint
    yields HOLD with the cached review noted (fail-safe even on replay)
  - ZIP members validated for absolute paths / `..` before extraction
    (defense-in-depth; Python's zipfile already sanitizes)
  - LLM bundle aggregation is budget-capped during assembly (no memory blowup
    on directories with many files)
  - Verified no-op: `Path.rglob` does not follow directory symlinks, so
    symlink-loop recursion cannot occur

## [1.2.2] — 2026-08-13

- Reachability probe rewritten as a plain TCP connect (the GET probe falsely
  failed on POST-only OpenAI-compatible endpoints, producing spurious HOLDs
  on cache hits)
