---
name: mfa_bypass
description: MFA bypass testing covering code reuse, brute force, response manipulation, and account recovery weaknesses
---

# MFA Bypass

Multi-Factor Authentication can be circumvented through implementation weaknesses even when correctly integrated at the UI level. Always test MFA flows independently of the underlying authentication.

## Attack Surface

**Code Weaknesses**
- TOTP/OTP codes not invalidated after use (replay attack)
- Long validity windows (> 5 minutes for TOTP)
- No rate-limiting on OTP submission endpoint
- OTP transmitted in response body or URL

**Flow Weaknesses**
- MFA step skippable by directly navigating to post-auth URL
- Session token issued before MFA completion
- `mfa_verified` flag set client-side (response manipulation)
- Backup codes exposed in API response or account settings

**Account Recovery Weaknesses**
- "Forgot MFA" flow bypasses MFA entirely with weak identity verification
- SMS OTP subject to SIM swapping
- Recovery codes not invalidated after use

## Testing Methodology

### Step 1 – OTP Replay
Submit a valid OTP, log out, log back in, and submit the same OTP again within the validity window. If it succeeds, codes are not invalidated after use.

### Step 2 – Rate-Limit Test
Send OTP submission requests in rapid succession (50–200 requests):
```
POST /api/mfa/verify
{"otp": "000000"}
...
{"otp": "999999"}
```
If no lockout occurs after ~10 failures, brute force is possible.

### Step 3 – Response Manipulation
Intercept MFA verification response. If the response contains:
```json
{"success": false, "mfa_required": true}
```
Modify to:
```json
{"success": true, "mfa_required": false}
```
and check if the application grants access.

### Step 4 – Skip MFA Step
After completing step 1 (username/password), directly request a protected resource before submitting the OTP. If the session cookie already grants access, MFA is not enforced server-side.

### Step 5 – Backup Code Exposure
```
GET /api/account/mfa/backup-codes
```
Check if backup codes are returned in plaintext or if exhausted codes remain valid.

### Step 6 – Parameter Tampering
```
POST /api/mfa/verify
{"otp": "123456", "user_id": "victim_user_id"}
```
Try substituting another user's ID to verify OTP in their context.

### Step 7 – OTP in URL or Logs
Check network requests for OTPs appearing in query parameters, referrer headers, or server access logs.

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| MFA step fully skippable | Critical |
| OTP brute-forceable (no rate limit) | High |
| Response manipulation grants access | High |
| OTP replay within valid window | Medium |
| Backup code exposure | Medium–High |

## Remediation

- Invalidate OTP immediately after first successful use
- Enforce server-side MFA state; never trust client-supplied `mfa_verified` flags
- Rate-limit OTP attempts (≤ 5 per minute, lockout after 10 failures)
- Expire TOTP codes at the 30-second window boundary
- Require re-authentication before revealing or regenerating backup codes
