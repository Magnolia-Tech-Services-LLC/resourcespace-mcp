# ResourceSpace MCP plugin

Native ResourceSpace plugin (`plugins/resourcespace_mcp/`) so Claude, ChatGPT, Grok, and other MCP clients can act as a ResourceSpace user. Actions go through `execute_api_call()` and that account’s permissions.

Supported: ResourceSpace 10.7 and 11, PHP 8.1+. HTTPS required.

## Install

1. Copy this directory to ResourceSpace's `plugins/resourcespace_mcp/` (underscore, not the GitHub hyphenated clone name).
2. Enable **Remote APIs** in ResourceSpace config (`$enable_remote_apis`).
3. Activate **MCP Server** on the plugin page and open its setup page.
4. Serve the site over HTTPS. If PHP sees HTTP behind a reverse proxy, enable **Behind a reverse proxy**.
5. Add the Apache or nginx snippet from the setup page to the **vhost** (many installs have `AllowOverride None`, so `.htaccess` will not apply). Apache needs `CGIPassAuth On` so `Authorization` reaches PHP. Claude/ChatGPT/Grok OAuth needs this rewrite. The ResourceSpace host must be able to fetch the connector's `https://` client ID metadata URL (for Claude, `claude.ai`).

ResourceSpace in a URL subdirectory (for example `https://example.com/rs`) is not supported for ChatGPT/Grok origin `/.well-known/` discovery. Use a host whose `$baseurl` has no path.

## Connector URL

Canonical paste URL (after the rewrite): `{baseurl}/mcp`

If `/mcp` 404s, API-key clients can paste `{baseurl}/plugins/resourcespace_mcp/mcp.php`. OAuth connectors (Claude, ChatGPT, Grok) still need the `/mcp` and `/.well-known/` vhost rewrite.

## Auth

- **OAuth (Claude / ChatGPT / Grok custom connector):** paste the URL, log in to ResourceSpace, Grant access.
- **API key (Claude Code and other header clients):** `Authorization: Bearer username:api_key` where `api_key` is the key on that user’s ResourceSpace account page.

Local file upload: `POST` multipart field `file` to `{baseurl}/plugins/resourcespace_mcp/pages/mcp_upload.php` as the same user (Bearer or an in-RS session).

## Tests

```bash
php tests/run.php
```

## License

BSD 3-Clause. Developed by Magnolia Tech Services. See `LICENSE`.
