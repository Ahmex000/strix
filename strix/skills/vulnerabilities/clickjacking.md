---
name: clickjacking
description: Clickjacking testing covering UI redressing, frame embedding, and X-Frame-Options / CSP bypass techniques
---

# Clickjacking

Clickjacking (UI redressing) tricks users into clicking hidden or disguised UI elements by overlaying transparent iframes on top of legitimate pages.

## Attack Surface

**Targets**
- Pages that perform sensitive actions (fund transfers, account changes, password resets, OAuth authorization, social actions)
- Pages missing `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`

**Defenses to Bypass**
- `X-Frame-Options: DENY / SAMEORIGIN`
- `Content-Security-Policy: frame-ancestors 'none' / 'self'`
- Frame-busting JavaScript

## Testing Methodology

### Step 1 – Check Headers
```
curl -s -I https://target.com | grep -i "x-frame-options\|frame-ancestors"
```
Missing or misconfigured headers indicate framing is allowed.

### Step 2 – Attempt Embedding
```html
<iframe src="https://target.com/sensitive-action" width="800" height="600" style="opacity:0.0001"></iframe>
```
If the page renders inside the iframe, the site is vulnerable.

### Step 3 – Frame-Buster Bypass
If JavaScript frame-busting is used (e.g., `if (top !== self) top.location = self.location`):
- Use `sandbox` attribute to disable JS: `<iframe sandbox="allow-forms" src="...">`
- Double-framing technique to confuse legacy bust code

### Step 4 – Construct PoC
Create a minimal HTML page that overlays the victim page and demonstrates a click being captured on a hidden sensitive button.

## Common Vulnerable Endpoints

- `/settings` — account deletion or email change
- `/transfer` — financial or data operations
- `/oauth/authorize` — third-party authorization grant
- `/2fa/disable` — two-factor authentication removal
- Social actions: like, follow, share buttons

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Sensitive action completable in one click (no CSRF token required) | High |
| Multi-step action, partial automation possible | Medium |
| Cosmetic/low-impact action only | Low |

## Reporting

- Include PoC HTML
- Screenshot or video showing the overlaid UI
- Confirm action was completed without user awareness
- Note whether `X-Frame-Options` or `frame-ancestors` is absent

## Remediation

```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
```
