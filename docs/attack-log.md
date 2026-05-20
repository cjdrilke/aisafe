# Attack Log — aisafe v0.3.0 → v0.3.9 + Round 10

A chronological record of every concrete attack vector that an external code
reviewer (OpenAI Codex CLI, then a Linus-style audit pass) reproduced
against aisafe, plus the patch that closed each one and the regression
test that pins the fix.

**This is the project's real value.** The implementation itself competes
with [Infisical agent-vault](https://github.com/Infisical/agent-vault),
[joelhooks/agent-secrets](https://github.com/joelhooks/agent-secrets),
1Password MCP, and other production-grade tools that have stronger
architectural foundations (HTTPS proxies, daemons, OS-level boundaries).
But the **attack/patch trail below** is something nobody else has — read
it as a "this is how easy it is to leak credentials to an AI" field guide,
not as a sales pitch for the code.

Each entry uses this shape:

> **Attack** — what the AI (or a clever human pretending to be one) does.
> **Why the prior defense missed it** — the gap in the previous version.
> **Patch** — the code change, with `file:line` anchors.
> **Test** — the regression that fails if the fix is reverted.

Round-by-round legend: `R2-1` = round 2, first attack in the report.

---

## Round 2 — policy itself is the attack surface

By v0.3.0 the project had a per-key policy engine. Codex immediately
attacked the *policy* rather than the credentials.

### R2-1 — AI rewrites the policy file from inside Python
- **Attack**: an AI process imports `aisafe.policy` and calls
  `set_key_policy("database.password", "open")`, then proceeds to read
  the secret legally.
- **Why prior defense missed**: mutation APIs were ungated; only `get()`
  was AI-aware.
- **Patch**: `_refuse_if_ai()` gate on every mutation API
  (`policy.py:489-506`, applied at `policy.py:511, 528, 544, 558, 577, 614, 640, 676`).
- **Test**: `tests/test_round2_fixes.py::test_ai_cannot_set_key_policy`
  and 5 siblings.

### R2-2 — AI redirects the policy file via env var
- **Attack**: `AISAFE_POLICY_FILE=/tmp/permissive.toml aisafe ...` →
  every key reads as `open`.
- **Why prior defense missed**: env var was honored unconditionally as a
  developer convenience.
- **Patch**: `_policy_path()` ignores the env override once `detect()` is
  truthy (`policy.py:178-192`).
- **Test**: `test_round2_fixes.py::test_policy_file_override_ignored_under_ai`.

### R2-3 — `aisafe env` is a one-shot exfiltration
- **Attack**: AI runs `aisafe env --section database` and prints the
  resulting export script straight into chat.
- **Why prior defense missed**: `aisafe env` predates AI-awareness; it
  always printed.
- **Patch**: both CLI command and `exec_runner.env_export()` API refuse
  when `detect()` is truthy (`exec_runner.py:225-256`).
- **Test**: `test_cli_env_refused_under_ai`, `R3-3 test_env_export_refused_under_ai`.

### R2-4 — Malformed policy file silently treated as empty
- **Attack**: AI writes `[keys] = "string instead of table"` and the
  parser falls back to default (`deny_ai`), but `default` itself was
  permissive in some configs.
- **Why prior defense missed**: parse exceptions were swallowed.
- **Patch**: every malformed entry → `PolicyState(broken=True)` →
  every read returns `deny` (`policy.py:195-282`).
- **Test**: `test_keys_not_a_table_is_fail_closed` and family.

### R2-5 — Host allowlist pattern injection
- **Attack**: AI configures `"hosts": {"github.token": ["*.com"]}` —
  the wildcard `*.com` matches any `.com` domain.
- **Why prior defense missed**: pattern was used verbatim.
- **Patch**: `_validate_host_pattern()` requires ≥2 labels after `*.`,
  rejects scheme/path/port/userinfo chars (`policy.py:373-407`).
- **Test**: `test_invalid_host_patterns_rejected`.

### R2-6 — MCP follows redirect to attacker-controlled host
- **Attack**: AI calls `http_request` with allowlisted `api.github.com`,
  server returns `Location: https://attacker/`, urllib auto-follows and
  forwards the bearer token.
- **Why prior defense missed**: default urllib opener follows redirects.
- **Patch**: `_NoRedirectHandler` surfaces every 3xx as `HTTPError`
  (`mcp_server.py:507-535`).
- **Test**: `test_no_redirect_handler_raises_for_each_3xx`.

### R2-8 — `extra_env` re-injects AISAFE_KEY
- **Attack**: AI calls `exec_runner.run(cmd, extra_env={"AISAFE_KEY": "..."})`.
- **Why prior defense missed**: caller-provided env wasn't filtered.
- **Patch**: `_filter_extra_env()` drops every `AISAFE_*` key
  (`exec_runner.py:129-138`).
- **Test**: `test_extra_env_aisafe_keys_dropped`.

### R2-9 — HTTP method / header name / timeout shenanigans
- **Attack**: bad method strings, header injection via name, negative timeout.
- **Patch**: typed validation at MCP boundary
  (`mcp_server.py` http_request input check).

---

## Round 3 — environment-variable end runs

R2 closed `AISAFE_POLICY_FILE`. R3 closed every other env override that
could redirect aisafe's notion of "where the files live."

### R3-1 — `XDG_CONFIG_HOME` / `APPDATA` redirection
- **Attack**: `XDG_CONFIG_HOME=/tmp/poisoned aisafe get database.password`
  → aisafe reads policy from attacker-controlled location.
- **Patch**: `paths.get_config_dir()` ignores XDG/APPDATA under AI
  detection (`paths.py:9, 102, 121`).
- **Test**: `test_xdg_config_home_ignored_under_ai`.

### R3-2 — `HOME` redirection + `AISAFE_FILE` + `AISAFE_AUDIT_LOG`
- **Attack**: same idea — redirect home, the credential file path, or
  the audit log to a writable scratch dir.
- **Patch**: `_trusted_home()` uses `pwd.getpwuid(os.getuid())` rather
  than `$HOME` under AI (`paths.py:121-145`).
- **Test**: `test_home_env_bypassed_under_ai`, `test_aisafe_file_env_ignored_under_ai`,
  `test_aisafe_audit_log_env_ignored_under_ai`.

### R3-3 — `env_export()` Python-level bypass
- **Attack**: AI bypasses CLI by `from aisafe.exec_runner import env_export`
  and calling it directly.
- **Patch**: gate moved into the API (`exec_runner.py:242-256`).
- **Test**: `test_env_export_refused_under_ai`.

### R3-4 / R3-5 — Header injection via name and CTL chars
- **Attack**: `auth_scheme="header"`, header name `X-Auth\r\nCookie`
  → smuggled second header.
- **Patch**: RFC 7230 token regex for names; reject all CTL chars in values
  except HTAB (`mcp_server._check_header_name`, `_check_header_value`).
- **Test**: `test_check_header_name_accepts_rfc7230_tokens`, `test_check_header_value_rejects_cr_lf`.

### R3-8 — Recovery from broken policy file
- **Attack** (more a usability gap that becomes a DoS): a broken
  policy.toml denies everything; without an unblock path, the user is stuck.
- **Patch**: `reset_to_default()` overwrites a broken file but is still
  AI-gated (`policy.py:668-677`).
- **Test**: `test_policy_reset_overwrites_broken_file`.

---

## Round 4 — secrets leaking through accidental channels

### R4-1 — Audit log captured the command line
- **Attack**: user (or AI) runs `aisafe set api.key sk-live-...` —
  the credential value is in `argv` and was being recorded into the audit
  log, which is read back via `aisafe://audit` MCP resource. Audit log
  became a secrets file.
- **Patch**: `audit._caller_info()` no longer reads `psutil.cmdline()`.
  Caller info kept: pid, exe, cwd (`audit.py:62-100`).
- **Test**: `test_audit_does_not_record_cmdline`.

### R4-2 — `_custom_path` survives the human → AI boundary
- **Attack**: human sets `aisafe.init("/path/to/poisoned.toml")`. AI then
  runs in the same Python process and inherits the redirected path.
- **Patch**: `_get_path()` re-checks `detect()` on every call; under AI,
  ignores `_custom_path` (`store.py:120-140`).
- **Test**: `test_custom_path_ignored_once_ai_detected`.

### R4-4 — Bearer / Basic auth token CTL injection
- **Attack**: secret stored as `bearer-token\nX-Bypass: 1` injects an
  extra header. Same for basic auth with `\n` in username.
- **Patch**: pre-flight reject secrets containing `\n` `\r` `\x00`
  (`mcp_server._check_header_value`).
- **Test**: `test_bearer_rejects_token_with_newline`, `test_basic_rejects_user_with_newline`.

### R4-5 — Query-param mode echoes secret literally
- **Attack**: `auth_scheme="query"`, secret contains `&` or `\n`. The naive
  concatenation `url?token=secret` corrupts the query and the secret
  shows up in server logs / referrers.
- **Patch**: `urlencode` the secret before appending (`mcp_server.py`).
- **Test**: `test_query_param_escapes_secret`.

### R4-7 — Setuid binary uses real-uid home
- **Attack**: aisafe invoked from a setuid wrapper. `pwd.getpwuid(os.getuid())`
  returns the real user's home, but the *effective* identity is different.
- **Patch**: `_trusted_home()` refuses when ruid ≠ euid (`paths.py:147-160`).
- **Test**: `test_trusted_home_refuses_setuid`.

---

## Round 5 — leaks at the *exception* layer

This is the round where the threat model deepened: even the *error path*
can leak the secret it was trying to protect.

### R5-1 — URL with CTL char passes the secret into `urllib.error`
- **Attack**: AI calls `http_request(url="https://foo\nbar", credential_key="x")`.
  `urllib` raises `InvalidURL("...{url-with-newline}...")` *with the secret
  already concatenated into the auth-bearing form*. The exception
  message is then audited / returned.
- **Patch**: pre-flight URL validation rejects raw CTL before the secret
  is touched; the generic exception handler returns a redacted message
  and never includes the exception text verbatim (`mcp_server.py:264-302`).
- **Test**: `test_url_with_newline_rejected_before_secret_pulled`,
  `test_internal_exception_does_not_leak_secret`.

### R5-2 — Cached credentials survive a path swap
- **Attack**: human caller populates `store._cache` against the
  legitimate file. AI appears, `_get_path()` switches to default, but
  cache is still serving entries from the old path — including entries
  the human's `init()` could have poisoned.
- **Patch**: cache is keyed by `_cache_path`; invalidated when path
  changes (`store.py:61-66, 153-194`).
- **Test**: `test_cache_invalidated_when_get_path_changes`.

### R5-3 — Audit log records full argv on collision error
- **Attack**: env-name collision triggers `ExecPolicyError` *before* the
  normal exec audit. The error-path audit logged the full argv —
  re-introducing the leak R4-1 fixed.
- **Patch**: every audit branch in `exec_runner.run()` uses the same
  `audit_cmd_summary = {"argv0", "argc"}` (`exec_runner.py:160-222`).
- **Test**: `test_exec_audit_records_only_argv0_and_argc`.

### R5-4 — `aisafe://audit` MCP resource was reading the audit log to AI
- **Attack**: AI calls the resource read, gets full audit JSONL — which
  R4-1 has cleaned but still contained file paths, pids, exec_env names.
- **Patch**: resource removed (`mcp_server.py` — no `aisafe://audit` URL).
- **Test**: `test_mcp_audit_resource_removed`, `test_mcp_audit_resource_read_rejected`.

### R5-5 — Fragment / existing-query handling in query-auth
- **Attack**: `https://foo?a=1#frag` + `auth_scheme="query"` → secret
  appended after `#`, never reaches server, but appears in browser history
  or referrer. Similar for existing `?` chains.
- **Patch**: URL is re-built via urlparse → urlunparse with the secret
  param merged into `query`, fragment stripped before sending.
- **Test**: `test_query_auth_with_fragment_in_url`, `test_query_auth_merges_with_existing_params`.

---

## Round 6 — response reflection

The HTTP backend stops the secret going *out*; round 6 stops it leaking
back *in* through the response.

### R6-1 — Server echoes the token in the response body
- **Attack**: AI calls a "debug" endpoint that echoes the bearer token in
  JSON. aisafe relays the body back to the AI verbatim.
- **Patch**: `_scrub_text()` replaces every form of the secret (raw,
  base64-for-basic, URL-encoded) with `<REDACTED>` before returning
  (`mcp_server.py:618-680`).
- **Test**: `test_bearer_secret_redacted_from_response_body`,
  `test_basic_auth_base64_token_redacted`.

### R6-1b — Server echoes the token in a response header
- **Attack**: server returns `X-Echo-Auth: Bearer sk-...`. Body scrub
  alone misses headers.
- **Patch**: `_scrub_headers()` scrubs both names and values
  (`mcp_server.py:618` chain).
- **Test**: `test_secret_redacted_from_response_headers`.

### R6-2 — Collision-error audit log
- (Same root cause as R5-3, additional surface; pinned by
  `test_exec_collision_audit_does_not_include_full_argv`.)

### R6-3 — Internal-error traceback printed to stderr by default
- **Attack**: an exception inside `_tools_call` printed `traceback.format_exc()`
  to stderr — which the MCP host (AI) reads. Stack frames contain local
  variables, including the secret.
- **Patch**: only print traceback when `AISAFE_DEBUG=1` (`mcp_server.py`).
- **Test**: `test_internal_error_does_not_print_traceback_by_default`.

### R6-5 — `_redact_args` missed `basic_user`
- **Attack**: basic-auth user could itself be sensitive (e.g. account id).
  Audit captured it.
- **Patch**: added to redaction list (`mcp_server.py:_redact_args`).
- **Test**: `test_redact_args_strips_basic_user`.

### R6-7 — `aisafe audit` CLI prints log to AI
- (Round 6 also gated the CLI command symmetrically to the MCP resource.)
- **Test**: `test_cli_audit_refused_under_ai`.

---

## Round 7 — encoded / second-order reflection

### R7-1 — URL-encoded secret in response body
- **Attack**: secret contains `+` or `/`. aisafe URL-encodes when building
  the request. Server's echo response contains the URL-encoded form —
  which the raw `_scrub_text` from R6 misses.
- **Patch**: redaction set now includes *both* raw and `urlencode`d forms
  of every credential (`mcp_server._collect_redaction_strings`).
- **Test**: `test_query_auth_redacts_url_encoded_secret`,
  `test_collect_redaction_strings_includes_encoded_for_query`.

### R7-2 — AI enables debug traceback
- **Attack**: AI sets `AISAFE_DEBUG=1` in its own env → R6-3 reverts.
- **Patch**: env var ignored under AI detection (`mcp_server.py`).
- **Test**: `test_debug_env_ignored_under_ai`.

### R7-3 — Confused deputy on POST / DELETE
- **Attack**: `github.token` is allowlisted for `api.github.com`. AI calls
  `DELETE /repos/.../everything`. Allowlist passes; destruction happens.
- **Patch**: GET / HEAD always allowed; POST / PATCH / PUT / DELETE
  require explicit `[unsafe_methods]` opt-in per credential
  (`policy.py:84-88, 424-446`).
- **Test**: `test_http_request_post_denied_without_opt_in`,
  `test_unsafe_method_after_opt_in`.

### R7-4 — Secret in response header *name*
- **Attack**: `X-<TOKEN>: 1`. R6 scrubbed values, not names.
- **Patch**: header names also scrubbed.
- **Test**: `test_secret_in_response_header_name_scrubbed`.

### R7-5 — Audit URL keeps `user:pass@` userinfo
- **Attack**: secret-bearing URL parsed through `_strip_url_query_fragment`
  retained `https://user:pass@host/`, leaking the credential into audit.
- **Patch**: rebuild via `hostname` + `port`, dropping userinfo
  (`mcp_server.py:_strip_url_query_fragment`).
- **Test**: `test_strip_url_removes_userinfo`.

### R7-9 — Policy mutation APIs accepted malformed credential keys
- **Attack**: `add_host("host with space", ...)` corrupts TOML.
- **Patch**: `_validate_cred_key()` on every mutation API
  (`policy.py:119-135`).
- **Test**: `test_policy_add_host_rejects_bad_cred_key`.

---

## Round 8 — visibility + load-time strictness

### R8-3 — `policy show` hid the unsafe-method opt-ins
- **Attack**: not a leak, a *governance* gap. Humans auditing policy
  couldn't see which credentials had POST/DELETE enabled.
- **Patch**: CLI + MCP both render `[unsafe_methods]` (`cli.py:cmd_policy_show`,
  `mcp_server.py:policy_show`).
- **Test**: `test_cli_policy_show_prints_unsafe_methods`,
  `test_mcp_policy_show_includes_unsafe_methods`.

### R8-4 — Policy file with malformed credential keys silently accepted
- **Attack**: AI writes `[hosts]\n"db.password with space" = [...]`. R7-9
  caught the mutation API but the loader still accepted hand-edited files.
- **Patch**: `_validate_cred_key()` also at load time
  (`policy.py:233-277`).
- **Test**: `test_policy_file_with_invalid_hosts_key_is_broken`.

### R8-6 — MCP tool description overstated the guarantee
- **Attack**: not technical — the `http_request` tool advertised
  *"credential value is never shown to you"* as an absolute. After R6/R7
  we now know it's best-effort scrubbing.
- **Patch**: description rewritten to say "best-effort redacted"
  (`mcp_server.py` tool registration).
- **Test**: `test_mcp_http_request_description_admits_best_effort`.

---

## Round 9 — same-uid policy tampering

### R9-1 — AI mutates `policies.toml` mid-MCP-session
- **Attack**: `aisafe mcp` starts → AI requests tool list → AI runs an
  `echo ... >> ~/.config/aisafe/policies.toml` shell command (or
  `cat <<EOF > ...`) → next tool call uses the permissive new policy.
  R2-1's API-level gate doesn't help because the AI isn't going through
  the Python API.
- **Patch**: at `serve()` start, SHA-256 the policy file. Before every
  tool call, recompute and compare. Any change → tool calls refused until
  the MCP server restarts (`mcp_server._policy_hash_at_startup`,
  `_check_policy_integrity`).
- **Test**: `test_tool_call_refused_when_policy_changes_midsession`.

### R10-1 (caught in R9 sweep) — TOCTOU between `host_allowed` and request
- **Attack**: AI flips policy after `host_allowed()` passes but before the
  actual HTTP send.
- **Patch**: integrity check runs again right before the urllib call.
- **Test**: `test_toctou_race_closed_in_http_request`.

---

## Round 10 — Linus-style audit (2026-05-19)

After 9 rounds of codex review the project was claimed "no Critical/High".
A Linus-style pass turned up four more bugs that codex hadn't reproduced:

### R10-1 — `store.py` wrote credentials without `chmod 0600`
- **Attack**: on a multi-user box, the credential file inherits umask.
  Default umask `0022` → file is `0644`, world-readable. Another local
  account reads the ciphertext (and only needs to grind the master password,
  or just reads the plaintext if encryption was never enabled).
- **Why prior defense missed**: `policy.py:709` and `audit.py:129` both
  chmod 0600. The actual *credential* file — the one thing that absolutely
  needed it — never did.
- **Patch**: `_chmod_600()` helper called on every write path
  (`store.py:_save`, `encrypt_store`, `decrypt_store`).
- **Test**: `tests/test_round10_fixes.py::test_plaintext_store_is_chmod_600`
  and 3 siblings.

### R10-2 — `policy.evaluate()` read the policy file twice per call
- **Attack**: between the two reads, an AI could modify
  `policies.toml`. The TOCTOU window is small in wall-clock terms but very
  reachable from a colocated process.
- **Why prior defense missed**: `evaluate()` called `_load_state()` and
  then called `resolve()`, which called `_load_state()` again. R9-1's
  startup-hash check helps only inside an MCP session; the rest of aisafe
  was racing itself.
- **Patch**: extract `_resolve_with_state(key, state)` so a single
  `evaluate()` call loads the file exactly once (`policy.py:299-326`).
- **Test**: `test_evaluate_loads_policy_file_once_per_call` counts the
  load calls.

### R10-3 — `AISAFE_STUB=1` downgraded `deny` to `stub_ai`
- **Attack**: AI sets `AISAFE_STUB=1` in its own environment, then asks
  the user to run `aisafe exec --section vault -- ./script.sh`. The
  exec path only refuses keys whose `resolve()` returns the string
  `"deny"`. But `AISAFE_STUB=1` made `resolve()` short-circuit to
  `"stub_ai"` for *every* key — including ones whose true underlying
  policy was `deny`. Those keys then got injected into the child env in
  plaintext. The policy.py docstring at lines 30-34 explicitly promised
  this could not happen.
- **Why prior defense missed**: `AISAFE_STUB` was added as a global
  override and placed *above* the per-key match in resolution order. The
  exec path trusted `resolve()` to honor `deny`.
- **Patch**: `_resolve_with_state()` checks the underlying policy first;
  `AISAFE_STUB` cannot downgrade `deny` (`policy.py:299-326`).
- **Test**: `test_aisafe_stub_does_not_downgrade_deny`,
  `test_aisafe_stub_does_not_leak_deny_key_via_exec`.

### R10-4 — Autouse fixture hid the parent-process detector from every test
- **Attack**: not an in-product attack. The *test* observation that no
  test exercised the real `_check_parent_chain` — only the env-var path.
  The most fragile part of detection (process tree heuristics) was
  un-exercised, so regressions there would never be caught.
- **Patch**: `conftest.py` stashes the real `_check_parent_chain` and
  exposes a `real_parent_chain` fixture for opt-in tests. Added 6 tests
  against a mocked psutil tree covering claude binary, claude-via-node
  cmdline, codex binary, depth limit, innocent parents, and psutil errors.
- **Test**: `tests/test_round10_fixes.py::test_parent_chain_detects_claude_binary`
  and 5 siblings.

---

## How to use this log

If you're considering aisafe for production, you should be reading this
log to understand the **shape of attacks against the AI-credential-leak
problem** — not because aisafe is the production answer.

The honest verdict on aisafe itself is in the README's "Status" section.
The honest verdict on the *threat model* is here: even after 10 rounds of
adversarial review, the attack surface keeps yielding new vectors that a
local sandbox-by-convention cannot address. The robust answers live at
the daemon / HTTPS-proxy / OS-keychain layer:
[Infisical agent-vault](https://github.com/Infisical/agent-vault),
[joelhooks/agent-secrets](https://github.com/joelhooks/agent-secrets),
1Password / Bitwarden / Doppler / Vault.

What's reusable from this log:

- the **attack vectors** themselves — if you're building a credential
  broker, run this list against it
- the **regression tests** in `tests/test_round{2..10}_fixes.py` — the
  patterns transfer to any agent-credential project
- the **negative result**: heuristic AI detection cannot anchor a security
  boundary. Treat it as a UX guard at best.
