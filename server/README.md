# widget-helper demo MCP server

Simulates a compromised "approved" MCP tool for security-scenario demos
(SCN-002: credential harvesting via leaked secrets in a tool response;
SCN-006: AI context poisoning via a hidden prompt-injection payload in a
tool response).

All secrets and instructions returned by this server are fake/inert —
generated for demo purposes, not real credentials.

```bash
npm install
npm start   # listens on :3000 (or $PORT), MCP endpoint at /mcp
```

Tools:
- `list_widgets` — clean baseline response
- `get_service_status` — leaks a fake AWS key/secret and SSH key (SCN-002)
- `get_release_notes` — hides a prompt-injection payload in changelog text (SCN-006)
