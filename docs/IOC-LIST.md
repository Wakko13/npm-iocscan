# IOC List – Indicators of Compromise

This document lists all known malicious packages and patterns detected by npm-iocscan, along with their threat sources and contexts.

> **Last Updated:** 2026-03-31
> 
> Contributions welcome. Submit updates with threat intelligence citations.

---

## Malicious Packages

| Package Name | Type | Source | Context | Detection |
|---|---|---|---|---|
| `plain-crypto-js` | Typosquat | npm registry | Impersonates `crypto-js`. Used in supply-chain attacks. | Exact match |
| `@anthropic-ai/claude-code` | Fake Publisher | npm registry | Fraudulent Anthropic package (2026). Similar to legitimate packages but distinct namespace. | Exact match |
| `npm-plugin` | Malicious Runner | npm registry | Generic malicious package installer. Often targets `postinstall` hooks. | Exact match |
| `npm-run` | Malicious Runner | npm registry | Obfuscated runner, attempts command execution via lifecycle hooks. | Exact match |
| `lodash4` | Typosquat | npm registry | Impersonates `lodash`. Minimal legitimate usage; primarily associated with compromised projects. | Exact match |
| `cors-any` | Exfiltration Vector | npm registry | CORS bypass tool. Often used in conjunction with data theft payloads. | Exact match |
| `http-server-proxy` | Proxy Hijack | npm registry | Man-in-the-middle tool. Intercepts and exfiltrates package install traffic. | Exact match |

---

## Lifestyle Script Hooks (Suspicious When Present)

| Hook Name | Risk Level | Context |
|---|---|---|
| `preinstall` | HIGH | Executes before dependency installation. Often used to download malicious code. |
| `postinstall` | HIGH | Executes after installation. Most common vector for supply-chain attacks. |
| `prepare` | MEDIUM | Git hook equivalent. Runs on `npm install` and `npm ci`. |
| `postuninstall` | MEDIUM | Runs after package removal. Can persist backdoors. |
| `preuninstall` | LOW | Rare. Can block removal operations. |
| `preupdate` | MEDIUM | Runs before package updates. Can prevent security patch installation. |

**Note:** Lifecycle scripts are not inherently malicious. Many legitimate packages use them for compilation, asset generation, etc. The scanner flags them for manual review and checks their content for suspicious shell commands.

---

## Exfiltration Endpoints & Patterns

| Pattern | Example | Risk | Notes |
|---|---|---|---|
| Discord Webhook URLs | `discord.com/api/webhooks/...` | CRITICAL | Data exfiltration, C2 communication |
| Telegram API | `telegram.*api` or `t\.me/...` | CRITICAL | Botnet C2, stolen credential collection |
| Pastebin | `pastebin.com/api/...` | HIGH | Source code, secrets, logs exfil |
| Webhook.site | `webhook.site/...` | HIGH | Attacker-controlled request logging |
| Beeceptor | `beeceptor.com/...` | HIGH | HTTP request capture for debugging attacks |
| curl/wget commands | `curl http://...` | HIGH | Direct file download (often in lifecycle scripts) |
| Invoke-WebRequest | `Invoke-WebRequest` (PowerShell) | HIGH | Windows payload download/execution |

---

## Shell Command Patterns

| Pattern | Risk | Context |
|---|---|---|
| `curl http://` | CRITICAL | Fetch and execute remote code |
| `wget http://` | CRITICAL | Fetch and execute remote code |
| `Invoke-WebRequest` | CRITICAL | PowerShell download (esp. Windows) |
| `powershell` (invocation) | CRITICAL | Shell command injection |
| `$()` (command substitution) | MEDIUM | Runtime code injection |
| `eval(...)` | CRITICAL | Dynamic code execution |
| `exec(...)` | CRITICAL | Child process spawning |

---

## Detection Methodology

### Static Analysis (Default)
- Package manifest parsing (JSON)
- Dependency object traversal
- Lifecycle script inspection
- Pattern regex matching
- No code execution

### Transitive Resolution (`-ScanTransitive`)
- Docker container + node:20-alpine
- `npm install --package-lock-only --ignore-scripts`
- Generates lockfile without running `postinstall` hooks
- Safe enumeration of full resolved tree
- Automated pattern re-check against resolved dependencies

---

## Known Limitations

1. **Obfuscation** – Base64, gzip, or other encoding can bypass pattern detection
2. **Runtime Execution** – Only static analysis; runtime behavior is not analyzed
3. **New IOCs** – Zero-day packages not yet cataloged may slip through
4. **False Positives** – Legitimate scripts using `curl` in CI contexts may be flagged
5. **NPM Registry Lag** – Recently unpublished packages may still appear in cached lockfiles

---

## Contributing IOCs

Found a new malicious package or pattern? Please submit:

1. **Package name** – Exact name from npm registry
2. **Detection date** – When first observed
3. **Threat source** – Blog post, CVE, GitHub issue, etc.
4. **Attack vector** – Typosquat, fake publisher, compromised author, etc.
5. **Context** – What data/systems does it target?

Submit via GitHub issue or pull request to this repository.

---

## References

- [npm Registry Audits](https://docs.npmjs.com/cli/v9/commands/npm-audit)
- [Snyk Package Vulnerability Database](https://snyk.io/vulnerability-database/)
- [CWE-506: Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)
- [OWASP Supply Chain Attacks](https://owasp.org/www-community/attacks/Supply_chain_attack)
