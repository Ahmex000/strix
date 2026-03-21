---
name: edge_cases
description: Edge case testing covering boundary conditions, encoding tricks, race conditions, and parser differentials that bypass standard security controls
---

# Edge Cases

Security controls often fail at boundary conditions. Testing edge cases systematically uncovers bypasses that standard payloads miss.

## Encoding and Representation

**URL Encoding Variants**
- Double encoding: `%2527` → decoded twice to `'`
- UTF-8 overlong encoding: `%c0%ae` → `.` (path traversal)
- Unicode normalization: `ＳＥＬＥＣＴ` → `SELECT` after NFKC

**Case and Whitespace**
- Mixed case: `SeLeCt`, `ScRiPt`
- Null bytes: `admin%00@evil.com` splitting email validation
- Newline injection: `%0d%0a` in headers
- Tab vs space: `SELECT/**/1` vs `SELECT 1`

**Content-Type Confusion**
- Send JSON as `application/x-www-form-urlencoded`
- Send XML where JSON is expected (XXE pivot)
- Charset parameter abuse: `charset=utf-7`, `charset=ibm037`

## Boundary Conditions

**Integer Boundaries**
- Max int32: `2147483647` → `2147483647 + 1` triggers overflow
- Negative IDs: `-1`, `-9999` may access special records
- Zero: ID `0` sometimes maps to admin or null record

**String Length**
- Empty string `""` vs absent parameter vs `null`
- Very long input (>= 10,000 chars) for buffer overflows / ReDoS
- Single character, single space, unicode zero-width space `\u200b`

**Array / Object Type Confusion**
- Sending `["admin"]` where `"admin"` (string) is expected
- `{"role": ["admin", "user"]}` vs `{"role": "admin"}`
- `null` vs missing key in JSON body

## Parser Differentials

**Path Traversal Edge Cases**
- `....//` (four dots, two slashes) normalised differently per OS
- `..%2f`, `..%5c`, `..%252f` (double-encoded slash)
- Windows UNC: `\\server\share`
- URL path confusion: `/api/../admin`

**Host Header Injection**
- `Host: target.com:80@attacker.com`
- `X-Forwarded-Host: attacker.com`
- Duplicate `Host` headers

**HTTP Method Override**
- `X-HTTP-Method-Override: DELETE`
- `_method=PUT` in POST body
- `X-Method-Override: PATCH`

## Race Conditions at Boundaries

- Submit two simultaneous requests to use a single-use coupon/token
- Concurrent account creation with the same username
- Parallel password reset requests to exhaust single-use token
- Double-spend: two simultaneous withdrawal requests

## Authentication Edge Cases

- Logging in with username containing leading/trailing whitespace
- Email case insensitivity: `Admin@example.com` vs `admin@example.com`
- Unicode homograph in username: `аdmin` (Cyrillic а) vs `admin`
- Expired session token still accepted after password change
- Password reset token valid after email address change

## API Versioning

- `/api/v1/` has security controls; `/api/v2/` or `/api/` (unversioned) may not
- Old versions left accessible without auth
- Mobile app endpoints (`/mobile/api/`) with relaxed validation

## Severity Assessment

Edge cases are context-dependent. Evaluate each finding based on:
- What security control is bypassed
- What impact the bypass enables (auth bypass = Critical, input validation bypass = variable)

## Testing Tips

- Fuzz with Burp Intruder using encoding and boundary payloads
- Compare responses for subtle differences (timing, length, status code)
- Test every input field in both authenticated and unauthenticated states
- Repeat tests after changing content-type, HTTP method, and parameter names
