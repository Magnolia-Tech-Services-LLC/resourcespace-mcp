# Spec: ResourceSpace MCP Server Plugin

## Context

Magnolia Tech Services wants ResourceSpace (Montala's open-source DAM, self-hosted) to speak MCP so Claude can act on the DAM directly — search, upload, tag, manage collections, administer — for whichever instance the plugin is installed on. Connecting requires an existing ResourceSpace user account. Every action runs as that user and is limited by that account's RS permissions (usergroup, `checkperm()`, resource/collection/field access). Three hard constraints shape everything below:

1. **It ships as a native ResourceSpace plugin** (`plugins/resourcespace_mcp/`), not a separate hosted service — it runs inside RS's own PHP request lifecycle, connects only to its own instance, and must follow Montala's plugin conventions so it upgrades cleanly with RS core.
2. **Tool count must stay flat regardless of API size.** The request was to follow "the Cloudflare MCP method." Research found that's actually Cloudflare's *Code Mode* — a sandboxed JS-code-execution pattern — which is the wrong shape for a PHP plugin with admin-level DB access (new attack surface, new runtime dependency, no payoff over the alternative). The confirmed substitute is a **search + execute** tool pair (the same outcome — flat context cost — implemented in plain PHP, matching Anthropic's own Tool Search Tool pattern and the common MCP "large API surface" tool-design pattern).
3. **Identity is an RS user, not a service account.** Auth is that user's existing API key (see §5) and, for Claude/ChatGPT/Grok connectors, OAuth 2.1 that ends in the same `setup_user()` path. There is no plugin-level "MCP admin" role and no second permission system.

**Supported RS versions:** 10.7 and 11. The live action catalog is always the reflected `api_*` set on *this* instance, so 10.7 simply has a smaller catalog (no comment/report `api_*`, no `/api/openapi.php`). Plugin PHP is 8.1+ (RS plugin coding standard). Do not use 8.2-only syntax.

## Research findings this spec relies on

- RS's API entry point is `/api/index.php` → `execute_api_call()`, which dispatches to `api_<name>()` functions found via `function_exists()` — **no central allowlist**. Permission checks (`checkperm()`, resource/collection/field-level filtering) live *inside* each `api_*` wrapper and the core functions they call — enforcement is per-function, not centrally guaranteed, and not blanket-admin.
- `execute_api_call()` lives in `include/api_functions.php`. Core wrappers live in `include/api_bindings.php`. `boot.php` loads **neither**. `api/index.php` includes `image_processing.php`, `api_functions.php`, `ajax_functions.php`, `api_bindings.php`, `login_functions.php`, and `dash_functions.php`. Plugin `api/api_bindings.php` files are pulled in by `register_plugin()` during boot. This plugin's endpoint must use the same include set as `api/index.php` or `execute_api_call()` / core `api_*` will be undefined.
- `execute_api_call()` **returns** a JSON-encoded string on success. It returns bool `false` (not JSON) when `function` is missing or `api_{function}` does not exist. It has no try/catch around `call_user_func_array`. Several `api_*` wrappers call `http_response_code()` (403/409/405/etc.); those must not leak onto the MCP HTTP response.
- Named query keys are already accepted (`function=do_search&search=cat`). Array-typed parameters are JSON-decoded **only** on the named-parameter branch; the positional `param1..paramN` branch passes raw strings and will TypeError on `array $data` signatures in PHP 8. Dispatch **must** use named parameters.
- Plugins already extend this surface via `plugins/<name>/api/api_bindings.php` (precedent: `consentmanager`, `licensemanager`). Core's own `pages/api_test.php` discovers the full callable set at runtime via `get_defined_functions()` + `ReflectionFunction` after the includes above.
- RS's request-signing auth (`sign = sha256(private_key + query_string)`) is **per-request** and cannot be satisfied by a static MCP client config (URL + fixed headers). It is not used here. The account page displays `get_api_key($userref)` = `hash("sha256", $userref . $api_scramble_key)`. That value does **not** change when the user changes their password. There is no per-user key revoke short of disabling/deleting the user or rotating global `$api_scramble_key` (invalidates every key).
- `check_api_key()` also accepts a signature made with `get_api_key($username)` (a different hash the account page does **not** show). MCP auth accepts **only** the displayed key (`get_api_key($userref)`). Do not dual-accept the username-derived hash — that would mint a second static secret.
- Per-user / usergroup IP restriction is enforced in `include/authenticate.php`, not in `check_api_key()` or `setup_user()`. Signed `/api/index.php` (userkey mode) does **not** include `authenticate.php`, so `/api/` already skips IP restriction. This plugin matches `/api/` and does **not** include `authenticate.php` on `pages/mcp.php` (that file also runs CSRF on POST and would break bearer clients).
- `setup_user()` returns false for download-quota users only when `API_CALL` is defined. `api/index.php` defines it before `setup_user()`. This plugin must too, and must 401 if `setup_user()` returns false, or those users get MCP as a bypass of the API restriction.
- `api_validate_upload_url()` (catalog id `validate_upload_url`) allowlists `parse_url()['host']` against `$api_upload_urls` when that config is set; if unset, it returns true for any valid URL with a path. New installs set `$api_upload_urls = array()`, which rejects every host. It blocks schemes in `BLOCKED_STREAM_WRAPPERS` (`php`, `file`) only — not private/link-local IPs. The fetch is `copy($url)` in `temp_local_download_remote_file()`, which follows redirects. Redirect-follow SSRF is existing `/api/` behavior; this plugin adds a pre-check on the **caller-supplied** URL (scheme + resolved IPs) and does not reimplement the fetch.
- `api_create_resource()` already accepts `$url` and `$metadata` in one call (API-specific, to reduce round trips) and runs `api_validate_upload_url` on the URL.
- RS 11 adds comment/report `api_*` functions and `/api/openapi.php`. Seed annotation descriptions from OpenAPI when that endpoint exists; on 10.7, seed from reflection + hand-written descriptions only. Vanilla PHP, no plugin-level Composer.
- `plugins/licensemanager/pages/setup.php` does **not** refuse inactive plugins — it calls `plugin_activate_for_setup()` so the setup page can render. Do not copy that onto `pages/mcp.php`.
- `setup_user()` may rewrite `$plugins` via `register_group_access_plugins()`. The "is this plugin enabled?" check on `pages/mcp.php` must run **before** `setup_user()`, against boot's `$plugins` (and `disable_group_select: 1` keeps group filtering from dropping it later).

## Recommended architecture

### 1. Plugin skeleton (Montala conventions)

```
plugins/resourcespace_mcp/
  resourcespace_mcp.yaml           # manifest — folder, filename, and name: must match
  mcp.php                     # MCP endpoint files; public paste URL is {baseurl}/mcp via rewrite
  pages/
    mcp.php                   # the MCP endpoint (bespoke — see §2); also the Montala pages/ alias
    setup.php                 # admin config page (see below)
  include/
    mcp_jsonrpc.php           # JSON-RPC 2.0 subset: initialize, tools/list, tools/call, ping
    mcp_catalog.php           # reflection bootstrap + curated-annotation merge (see §3)
    mcp_dispatch.php          # named-param query string → execute_api_call() (see §4)
    mcp_auth.php              # bearer-token check + setup_user (see §5)
  hooks/
    all.php                   # HookResourcespace_mcpAllExtra_checks
  config/
    catalog_annotations.php   # hand-curated metadata, keyed by execute_api_call function name (no api_ prefix)
    config.php                # enable-toggle and trusted-proxy defaults
  languages/
    en.php                    # strings this plugin adds
```

`resourcespace_mcp.yaml` (values unquoted — RS splits on the first `:`):

```
name: resourcespace_mcp
title: MCP Server
author: Magnolia Tech Services
version: 1
desc: MCP server so AI assistants can act as a ResourceSpace user
category: API
config_url: /plugins/resourcespace_mcp/pages/setup.php
info_url: /plugins/resourcespace_mcp/pages/help.php
disable_group_select: 1
```

`disable_group_select: 1` is required so group-level disable cannot leave `pages/mcp.php` reachable for groups that "don't have" the plugin.

`pages/mcp.php` request order (do not reorder):

1. `$disable_browser_check = true` (must be set **before** `boot.php`; if `$browser_check` is on, `browser_check()` emits HTML and exits).
2. `include boot.php`.
3. Same API runtime includes as `api/index.php`: `image_processing.php`, `api_functions.php`, `ajax_functions.php`, `api_bindings.php`, `login_functions.php`, `dash_functions.php`.
4. This plugin's `include/mcp_*.php`.
5. If `resourcespace_mcp` is not in `$plugins` → HTTP 403, JSON-RPC error, stop. Do **not** call `plugin_activate_for_setup()` here.
6. HTTPS check (§2). Fail → HTTP 403, JSON-RPC error.
7. Method / Accept / body checks (§2): unauthenticated GET/HEAD → 401 + `WWW-Authenticate`; authenticated GET → 405; DELETE → 405; `Accept` missing `application/json` → 406; JSON-RPC batch → 400; parse error → 400.
8. Bearer auth (§5). Fail → HTTP 401. `setup_user()` happens here, after the plugin-enabled check.
9. JSON-RPC method dispatch.

`pages/mcp.php` does **not** include `authenticate.php`.

`pages/setup.php` (admin UI):

- `include boot.php` then `authenticate.php`; `checkperm('a')` or exit.
- If the plugin is not in `$plugins`, call `plugin_activate_for_setup('resourcespace_mcp')`.
- CSRF-protected POSTs via RS form tokens (`generateFormToken` / `config_gen_setup_post`).
- Controls on this page (complete list):
  1. Connector URL (read-only) and link to the in-RS help page.
  2. Read-only `$enable_remote_apis` status.
  3. Plugin enable toggle (in addition to `$enable_remote_apis`).
  4. Trusted-proxy toggle (trust `X-Forwarded-Proto`) — **default off**.
  5. Per-category allowlist Yes/No selects (§3) — curated categories default on, `uncurated` default off.
  6. Origin rewrite snippets: `{baseurl}/mcp` → plugin `mcp.php`, plus `/.well-known/` OAuth discovery. Apache uses `%{REQUEST_URI}` so the same rules work in a vhost or DocumentRoot `.htaccess`. nginx locations belong in the `server` block. Rewrite targets include the `$baseurl` path (where the plugin files live). Origin discovery is still `/.well-known/` on the site root. The paste URL is `{baseurl}/mcp` (the ResourceSpace install URL plus `/mcp`), not a Magnolia-branded plugin path. Existing `/mcp.php` and `pages/mcp.php` URLs remain resource aliases.
  7. Authenticator-app note and revoke-all-tokens button (with confirm).
  8. If this setup request arrived as HTTP with `X-Forwarded-Proto: https` and the reverse-proxy toggle is off, show a warning to enable it.
- There is **no upload UI** on setup or help. MCP tools still upload (`rs_upload_resource`, `create_resource` with a URL, `pages/mcp_upload.php`).
- There is **no catalog refresh control**. The catalog cache key includes PHP version, RS version, plugin list, and annotations mtime; a miss rebuilds on the next MCP request.

`hooks/all.php` implements `HookResourcespace_mcpAllExtra_checks`: return FAIL when `$enable_remote_apis` is off, the plugin toggle is off, or the trusted-proxy/HTTPS setup would refuse every request. Keep the hook body trivial — a fatal in `hooks/all.php` takes down the DAM.

### 2. Transport: bespoke endpoint, not `api_bindings.php`

MCP's JSON-RPC envelope (`initialize` / `tools/list` / `tools/call`) can't ride RS's `function=X&param1=...&sign=...` dispatch, so `pages/mcp.php` is a standalone endpoint, not an `api_bindings.php` registration. It still **dispatches through `execute_api_call()`** rather than reimplementing RS's function-calling — that's the one piece reused from core; everything transport-level is new.

- Protocol: MCP streamable HTTP, **stateless, JSON response mode** — one HTTP request per JSON-RPC message, no long-lived SSE stream, no session resumption, no `Mcp-Session-Id` issued. JSON response mode is valid when the client `Accept` lists `application/json` (MCP clients MUST send both `application/json` and `text/event-stream`). If `Accept` is only `text/event-stream`, return 406.
- `protocolVersion` is pinned to **`2025-03-26`**. `initialize` returns that version, `serverInfo` (name `ResourceSpace`, version from the yaml), and `capabilities` (tools only — no resources/prompts/sampling, see §7). Do not negotiate a later version that drops this handshake.
- `MCP-Protocol-Version` on post-initialize requests: missing → assume `2025-03-26`; unsupported/mismatch → HTTP 400.
- `notifications/initialized` with no JSON-RPC `id` → HTTP 202, empty body. If a client wrongly sends an `id`, return a JSON-RPC result (empty object) with HTTP 200.
- `ping` returns an empty result object.
- Implementation: hand-rolled JSON-RPC 2.0 subset (`initialize`, `tools/list`, `tools/call`, `ping`) in vanilla PHP. No Composer, no MCP SDK.
- HTTPS required. `$baseurl` beginning with `https://` is **not** proof this request is TLS (`boot.php` only rewrites `$baseurl` when `SERVER_PORT == 443`; it does not read `X-Forwarded-Proto`). Check the request: `$_SERVER['HTTPS']` is on, **or** (only if the trusted-proxy toggle is on) `X-Forwarded-Proto` is `https`. Refuse otherwise. Also refuse if configured `$baseurl` scheme is not `https`.
- Do **not** 403 machine endpoints when `Origin` is a connector host (`https://claude.ai`). Bearer APIs are not cookie CSRF. `mcp_origin_ok()` is unused on the request path. `oauth_authorize.php` is a same-origin RS page and validates `isValidCSRFToken` on POST.
- Unauthenticated GET/HEAD → 401 + `WWW-Authenticate` (OAuth discovery). Authenticated GET → 405. Reject JSON-RPC batch arrays with HTTP 400. Reject unknown methods with JSON-RPC `-32601`, HTTP 200. HTTP DELETE → 405. Parse error → HTTP 400, `-32700`. Invalid request → HTTP 400, `-32600`.
- Every JSON-RPC method — including `initialize`, `tools/list`, and `ping` — requires a bearer token from §5 (API key **or** OAuth access token). Missing/invalid token → HTTP 401, JSON-RPC error `{"jsonrpc":"2.0","error":{"code":-32001,"message":"Unauthorized"},"id": <request id or null>}`, plus `WWW-Authenticate` for connector discovery (see OAuth connector spec). Unauthenticated GET on `mcp.php` is 401 (not 405) once OAuth ships.
- Successful JSON-RPC responses: HTTP 200, `Content-Type: application/json`.
- `execute_api_call()` isolation in `mcp_dispatch.php`: capture `http_response_code()` before the call and restore it after; wrap in try/catch for `Throwable`; map bool `false`, throwables, and decoded error payloads to `tools/call` `isError: true` with a text message. Never let `api_*` `http_response_code(403/409/…)` become the MCP transport status. Successful tool calls stay HTTP 200 with a JSON-RPC result.

### 3. Action catalog: reflection + curated annotations, not a hand-typed list

Catalog identity is the `execute_api_call()` `function` value — **no `api_` prefix** (`do_search`, not `api_do_search`). Passing `function=api_do_search` looks up `api_api_do_search` and returns `false`. Annotations, deny-list, allowlist, and `rs_execute_action`'s `action` param all use this ID. Strip an `api_` prefix if reflection yields the PHP function name.

Reflection bootstrap (same include set as `pages/api_test.php`): after the §1 includes, take `get_defined_functions()['user']` filtered to names starting `api_`, minus the deny-list. That picks up wrappers in `api_functions.php` (`login`, `validate_upload_url`, `get_daily_stat_summary`) and plugin files that do not sit at `api/api_bindings.php`.

Curation (descriptions, categories, synonyms, destructive/read-only hints, non-scalar serialization) is the bulk of this deliverable (roughly 90–150+ entries, growing with active plugins). Annotations are hand-curated in `catalog_annotations.php`. RS 11-only `api_*` functions appear as `uncurated` until annotated.

**Category enum** (closed; this is the allowlist and the empty-search result list):

| Category        | Meaning                                              |
|-----------------|------------------------------------------------------|
| `resources`     | Resource CRUD, files, alternatives, related          |
| `search`        | Search and dash search                               |
| `collections`   | Collections, featured collections                    |
| `metadata`      | Fields, nodes, tabs                                  |
| `users`         | Users, usergroups, `checkperm`                       |
| `system`        | Status, stats, reports                               |
| `plugins`       | Plugin-contributed `api_*` that have been curated    |
| `uncurated`     | Reflected, not yet reviewed                          |

Every curated entry maps to exactly one of the first seven. Uncurated entries are `uncurated`.

**Reference taxonomy** (sizing aid only; live catalog is the reflected set for *this* instance):
- Resource CRUD & files — `create_resource`, `get_resource_data`/`get_resource_field_data`, `put_resource_data`, `delete_resource`, `copy_resource`, `upload_file`/`upload_file_by_url`/`upload_multipart`, `replace_resource_file`, `add_alternative_file`, `get_related_resources`, `get_resource_log`
- Search — `do_search`, `search_get_previews`, `get_dash_search_data`
- Collections — `create_collection`, `add_resource_to_collection`/`collection_add_resources`, `get_featured_collections`, etc.
- Metadata/fields/nodes (tagging is node-based, no separate tag API) — `get_field_options`, `update_field`, `get_nodes`/`set_node`
- Users/permissions/usergroups — `checkperm`, `get_users`, `new_user`/`save_user`
- System/reporting — `get_system_status`, `get_daily_stat_summary`; comments/reports `api_*` only if present on this RS version
- Tabs/dashboard — `save_tab`, `reorder_featured_collections`
- Plugin-contributed bindings — whatever's active and reflected
- **Known gap**: external sharing (`generate_share_key`, `create_upload_link`) may be internal helpers rather than `api_*`-bound — do not imply coverage the reflection pass cannot reach.

**Uncurated functions** (reflected, not in `catalog_annotations.php`): they stay **in the catalog** so upgrades don't silently drop new `api_*` functions, but they are **not callable by default**. `rs_search_actions` returns them only on broad/explicit queries, flagged `"unannotated": true`, `destructiveHint: true`. The `uncurated` category **defaults disabled**. Enabling it is an explicit admin action. "Full scope" means the catalog *contains* the reflected set; it does not mean unreviewed functions are executable on a fresh install.

**Deny-list** (applied after reflection, before search, execute, and promoted tools). Catalog IDs:

| ID                     | Why |
|------------------------|-----|
| `login`                | `api_login` mints a session key |
| `validate_upload_url`  | SSRF oracle if called as an action |

If reflection on this instance yields any other `api_*` whose return value is a session or user key, add it to this table in code (keep the shipped table as the minimum). `get_session_api_key()` is not an `api_*` function and will not appear in reflection. If `do_report` is reflected and the wrapper defaults `$download = true` (CSV attachment / exit), deny-list it until a curated annotation can pass `download=false`; do not let it break the JSON-RPC envelope.

**Allowlist vs user permissions (two layers, both required):**

1. Site-wide category allowlist on `setup.php` — which *families* of actions this MCP endpoint will even consider. Defaults: all curated categories **enabled**, `uncurated` **disabled**. An admin can turn e.g. `users` or `system` off for every MCP client.
2. The acting RS user's permissions — `setup_user()` then `api_*` wrappers. A contributor whose key is in the `Authorization` header cannot create users even if category `users` is enabled.

A call is refused if the action is deny-listed, its category is disabled, **or** the `api_*` wrapper denies the user. Promoted tools use the same two layers:

| Promoted tool            | Category      |
|--------------------------|---------------|
| `rs_search`              | `search`      |
| `rs_get_resource`        | `resources`   |
| `rs_create_resource`     | `resources`   |
| `rs_upload_resource`     | `resources`   |
| `rs_update_metadata`     | `metadata`    |
| `rs_manage_collection`   | `collections` |
| `rs_check_permissions`   | `users`       |

**Storage**: `config/catalog_annotations.php` ships as read-only, source-controlled content — not written at runtime. The per-category allowlist is stored via RS's plugin config (`set_plugin_config` / `get_plugin_config`). The built catalog **cache** lives in `get_temp_dir()`, not in plugin config: `set_plugin_config()` rewrites the whole row and `config_clean()` blanks any string containing `<script`. Do not mix a large reflection blob with allowlist writes in one config update.

**Caching**: cache reflection + annotation merge, keyed on PHP version, RS version, active-plugin set, annotations file mtime, this catalog PHP file mtime, core `include/api_bindings.php` mtime, and each enabled plugin's `api/api_bindings.php` mtime. A key miss rebuilds on the next MCP request. The includes in §1 are **not** cached — `execute_api_call()` needs the functions defined in that request.

**Keeping the catalog honest**: new `api_*` functions appear as `uncurated` after a cache miss (PHP/RS version or plugin-list change). They stay hidden while the unreviewed category is off. There is no admin refresh or annotation-edit control.

### 4. Tools exposed (flat count, regardless of catalog size)

Every promoted tool and `rs_execute_action` calls `execute_api_call()` (named parameters). **Never** call core functions (`get_resource_data`, `update_field`, `do_search`, `checkperm`, `upload_file_by_url`, …) from MCP code. Core `get_resource_data()` has no access check; `api_get_resource_data()` does. That is how "limited per user account" is enforced.

```
rs_search_actions(intent, category?, limit=10)     -> matching actions with schema + category + read/write hints
rs_execute_action(action, params)                   -> execute_api_call(); isError on deny-list / disabled category / api_* failure

# promoted hot-path tools (skip the discovery round-trip for the common case):
rs_search(query, resource_type?, limit=50, offset?) -> do_search (fetchrows=limit, offset=offset); readOnlyHint: true
rs_get_resource(ref)                                -> get_resource_data then get_resource_field_data; readOnlyHint: true
rs_create_resource(resource_type, url?, initial_metadata?) -> create_resource (native one-shot: type + optional url + optional metadata JSON); destructiveHint: false, but a write
rs_upload_resource(ref, url)                        -> upload_file_by_url after plugin SSRF checks; see §6 — URL-only
rs_update_metadata(ref, field, value)               -> update_field; destructiveHint: false, but a write
rs_manage_collection(action, collection_ref?, resource_refs?) -> create_collection / add_resource_to_collection / remove_resource_from_collection / collection_add_resources / collection_remove_resources via execute_api_call, selected by `action`; destructiveHint: true (fixed)
rs_check_permissions(permission_code, resource_ref?) -> checkperm (+ get_resource_access / get_edit_access when resource_ref given); readOnlyHint: true
```

Names in the arrows above are catalog IDs (`execute_api_call` `function=` values), not core PHP functions.

`rs_create_resource` accepts optional `url` because `create_resource` already uploads by URL in the same API call. `rs_upload_resource` remains for attaching a file to an existing ref. Do not wrap both `do_search` and `search_get_previews` in `rs_search` — `search_get_previews` has no `offset`; pagination belongs on `do_search`. Preview URLs are a separate execute/search_actions concern, not stuffed into the hot-path search payload.

`rs_search_actions` matches `intent` against name + description + category + a small synonym list per curated entry (token-overlap scoring; no embeddings). Results capped at `limit` (default 10). Uncurated results (only if that category is enabled) return reflection param names, not a full schema, and are labeled as such. A query that matches nothing returns the category list.

`rs_execute_action` validates `action` against the catalog minus the deny-list minus disabled categories, then dispatches. Writes are attributed to the acting user in `resource_log` because §5 binds the request via `setup_user()`.

**Annotations are per-tool, not per-call.** `rs_execute_action` and `rs_manage_collection` both advertise a fixed `destructiveHint: true`. Per-action hints live only as data in `rs_search_actions` results.

**Result size**: inject limits **before** dispatch. If the caller omitted a row cap, default `fetchrows` (or equivalent) to 50 for: `do_search`, `search_get_previews`, `get_users`, `get_resource_log`, `resource_log_last_rows`. After `execute_api_call()`, `json_decode` the result, truncate the data structure if still over 50KB encoded, re-encode, and append a truncation notice. Never `substr()` the JSON string. Promoted `rs_search` always passes `fetchrows`.

**Param mapping**: build the query with **named** keys (`function=update_field&resource=12&field=8&value=…`), URL-encoded. JSON-encode array/object values (the named branch of `execute_api_call()` JSON-decodes parameters typed `array`). Do not emit `param1..paramN`. Curated entries may note comma-separated list vs JSON for a given field; default is JSON for arrays.

### 5. Auth: ResourceSpace user account, API key as Bearer

Connecting to this MCP server requires an existing ResourceSpace user account. There is no anonymous mode and no plugin-wide service user.

**V1 credential:** `Authorization: Bearer <username>:<key>` where `<key>` is the API key shown on that user's RS account page (`get_api_key($userref)`). Split the bearer value on the **first** colon. Lookup `get_user_by_username($username)`; if false → 401. Compare the supplied key to `get_api_key($userref)` with `hash_equals()`. Do not accept `get_api_key($username)`. Call RS's `get_api_key()` — never reimplement the hash. Read the header from `HTTP_AUTHORIZATION`, else `REDIRECT_HTTP_AUTHORIZATION`, else `getallheaders()` key `Authorization` (case-insensitive). Apache `mod_php` often omits `$_SERVER['HTTP_AUTHORIZATION']`.

**OAuth connector (v2):** Static `Authorization: Bearer <username>:<key>` remains valid. OAuth access tokens (no colon) map to an RS `userref` and then run this same `setup_user()` path — not a parallel permission system. Do not invent an OAuth AS by forking `simplesaml` or the YouTube/Vimeo OAuth *client* plugins.

**HMAC request signing is not used.**

On success, `mcp_auth.php` must, in this order:

1. `define("API_CALL", true)` (before `setup_user()`).
2. `$validuser = setup_user(get_user($userref))`. If false → 401 (covers download-quota users and bad user records).
3. `update_user_access(0, ["last_browser" => isset($_SERVER["HTTP_USER_AGENT"]) ? substr($_SERVER["HTTP_USER_AGENT"], 0, 250) : "MCP"])`.
4. `set_sysvar("last_api_access", date("Y-m-d H:i"), false)`.

This is RS's proven API auth path. It is what makes `checkperm()` and resource access inside `api_*` see the right user.

**User-account limits are the permission model.** No additional permission layer on top of (a) the site-wide category allowlist and (b) RS `api_*` checks. If an `api_*` function lacks a permission check, that is an existing property of RS core, already reachable with that user's key via `/api/` — not a gap this plugin introduces. MCP code must not widen it by calling core functions.

**Revocation (settled):** the key is `hash("sha256", $userref . $api_scramble_key)`. Password change does **not** rotate it. Operational revoke: disable or delete the RS user, or rotate `$api_scramble_key` (all users).

**IP restriction (settled):** match `/api/` — not enforced on this endpoint. Do not include `authenticate.php` on `pages/mcp.php`.

**Controls:**

- Endpoint requires `$enable_remote_apis` **and** the plugin's own enable toggle on `setup.php`.
- Per-category allowlist as in §3 (curated categories default on, `uncurated` default off).
- HTTPS-only, as in §2.

### 6. File uploads: URL-only, no byte payloads

An MCP `tools/call` carries a JSON params object, not a multipart body — `upload_multipart` and `upload_file` don't fit. `rs_upload_resource` wraps `upload_file_by_url` only (via `execute_api_call`). Base64 bytes in params are rejected: DAM originals are tens of MB and would land in the model context. A later out-of-band HTTP upload endpoint is a separate feature, not a tool parameter.

Before calling `upload_file_by_url` / `create_resource` with a URL:

1. Reject non-`http`/`https` schemes.
2. Resolve the caller-supplied host and **refuse** if any address is private, loopback, link-local, or a cloud metadata range (`169.254.169.254`, `fd00:ec2::254`, etc.). `api_validate_upload_url()` does not do this.
3. Honor `$api_upload_urls` when it is a non-empty list. If unset, step 2 still applies (do not allow-all). If it is an empty array (new installs), fail with a message that names `$api_upload_urls` — not a generic `false`.
4. Then `execute_api_call` as usual (`api_upload_file_by_url` still runs `api_validate_upload_url` itself).

Do not replace `temp_local_download_remote_file()` / `copy()`. Redirect following after this pre-check is the same residual SSRF `/api/` already has; this plugin does not widen it.

`rs_create_resource` with `url` uses the same pre-checks, then `create_resource`.

Originals from the user's computer are not JSON-RPC parameters. POST
`multipart/form-data` to `{baseurl}/plugins/resourcespace_mcp/pages/mcp_upload.php`
as the same RS user (Bearer). Help.php does not host an upload form.

### 7. Scope boundary

Out of scope for this version:

- MCP `resources` and `prompts` primitives ("resource" is overloaded with RS's domain model).
- Byte/multipart inside JSON-RPC tools/call.
- SSE streams, session IDs, resumability.

OAuth connectors (Claude/ChatGPT/Grok login): the plugin-path paste URL is a resource alias; the paste URL is `{baseurl}/mcp`.

Local file POST: Bearer to `mcp_upload.php`; no help-page form.

## Verification

1. Enable the plugin on a test RS 10.7 or 11 instance, hit `{baseurl}/mcp` (rewritten to plugin `mcp.php`) with `initialize` and confirm `tools/list` returns exactly the fixed tool set (not one tool per `api_*` function). Confirm `protocolVersion` is `2025-03-26`. Confirm `pages/mcp.php` is the same endpoint.
2. Call `rs_search_actions` with a few intents (e.g. "upload a photo", "find resources tagged X", "list users") and confirm it surfaces the right actions with correct category/hints.
3. As a **non-admin** user (locked-down usergroup, not an admin account): call promoted `rs_get_resource` on a confidential resource the user cannot see — must fail, not return unrestricted `get_resource_data()` rows. Call `rs_execute_action` for a read (`do_search`) and a write (`update_field`); results must match that user's `/api/` permissions. Call `new_user` (if category `users` is enabled) — must fail for that user the same way `/api/` would, and the HTTP status of the MCP response must remain 200 with `isError: true`, not 403.
4. Confirm a deliberately-uncurated function (temporarily remove one entry from `catalog_annotations.php`) still appears via broad search only when the `uncurated` category is explicitly enabled, flagged unannotated with `destructiveHint: true`, and is refused when that category is left at its default-disabled state. Confirm a disabled curated category is refused for **both** `rs_execute_action` and the matching promoted tool.
5. Add this as a custom MCP server in **Claude Code's** MCP config (arbitrary `Authorization` headers) pointed at `{baseurl}/mcp` + `username:key` of a real RS user, and drive search → create → upload-by-URL → tag → collection as that user. Confirm writes show in `resource_log` as that user.
6. Negative paths: missing/invalid bearer → 401 on every method including `initialize`; deny-listed `login` and `validate_upload_url` refused; plaintext HTTP refused when accessed directly (not through the trusted-proxy path); `do_search` without a caller limit does not load the full result set (`fetchrows` injected); truncated results are still valid JSON; connector `Origin` on machine endpoints is not a 403; `users` category off → `rs_check_permissions` refused.

## Operational logging

Auth failures, deny-list hits, and disabled-category refusals are logged with `log_activity()`. Redact the `Authorization` header and any copied key material. This is separate from `resource_log`, which already records successful writes as the acting user.
