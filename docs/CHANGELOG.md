# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] – 2026-03-31

### Added
- Initial release of npm-iocscan
- Static analysis of package manifests and lockfiles
- Detection of 7 known malicious packages
- Lifecycle script inspection (preinstall, postinstall, prepare, etc.)
- Exfiltration indicator detection (Discord, Telegram, webhooks, shell commands)
- Transitive dependency resolution with Docker (safe, no script execution)
- Multi-format support (package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml)
- Severity classification (CRITICAL, HIGH, MEDIUM)
- Comprehensive documentation (README, USAGE, IOC-LIST)
- Pester test suite with fixtures
- AGPL-3.0-only license

### Documentation
- README.md – Quick start and feature overview
- USAGE.md – Detailed usage guide with examples
- IOC-LIST.md – Complete list of indicators with context
- CHANGELOG.md – This file

---

## Future Releases (Planned)

### [1.1.0] – Q2 2026 (Planned)
- Add JSON output format for CI/CD integration
- Support SARIF format for GitHub Advanced Security
- Add baseline/whitelist capability
- Performance optimization for large monorepos
- PowerShell Gallery publishing

### [1.2.0] – Q3 2026 (Planned)
- Integration with npm audit for CVE correlation
- SBOM (Software Bill of Materials) generation
- Custom IOC list support
- Rate limiting detection
- Behavioral analysis for novel packages

---

## How to Contribute

Found a new IOC? Malicious package? Please submit:

1. Open a GitHub issue with:
   - Package name
   - Detection date
   - Threat source (blog, CVE, etc.)
   - Attack vector (typosquat, compromised, etc.)

2. Or submit a pull request updating:
   - `npm-iocscan.ps1` – Add to `$iocPatterns`
   - `docs/IOC-LIST.md` – Document the IOC
   - `tests/fixtures/` – Add test case

---

## Security Advisories

### CVE / Threat Correlation

- **2026-03-15** – Anthropic Claude Code compromise alert
  - Fake package: `@anthropic-ai/claude-code`
  - Added to detector immediately upon report
  - See: [npm registry security alert](https://example.com)

