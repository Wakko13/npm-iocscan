# npm-iocscan

A comprehensive PowerShell security scanner for Node.js projects that detects malicious npm packages, suspicious lifecycle scripts, and supply-chain compromise indicators—without executing package installation scripts.

## Features

- **Malicious Package Detection** – Flags known typosquats and compromised package names
- **Lifecycle Script Analysis** – Identifies `preinstall`, `postinstall`, `prepare` and other hooks that may contain malicious code
- **Exfiltration Indicator Detection** – Searches for webhook endpoints, C2 callbacks, and shell commands
- **Safe Transitive Resolution** – Resolves full dependency trees in isolated Docker containers without executing scripts
- **Multi-format Support** – Scans `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`
- **Severity Classification** – Categorizes findings as CRITICAL, HIGH, or MEDIUM

## Quick Start

```powershell
# Static analysis (fast, no docker required)
./npm-iocscan.ps1 -Path .

# Full scan with transitive dependency resolution
./npm-iocscan.ps1 -Path . -ScanTransitive

# Scan a specific project directory
./npm-iocscan.ps1 -Path ./path/to/project -ScanTransitive
```

## Execution Model

This project is intentionally direct-run only.

```powershell
# Run in place with no installation, profile modification, or persistence
./npm-iocscan.ps1 -Path .
./npm-iocscan.ps1 -Path . -ScanTransitive
```

## IOC Coverage

The scanner detects:
- **Malicious packages** – Known typosquats and compromised package names (see [IOC-LIST.md](docs/IOC-LIST.md))
- **Lifecycle hooks** – preinstall, postinstall, prepare, preuninstall, postuninstall
- **Exfiltration patterns** – Discord webhooks, Telegram API calls, pastebin, beeceptor, curl/wget commands
- **Shell execution** – `eval()`, `exec()`, command substitution, PowerShell invocation

## Documentation

- **[USAGE.md](docs/USAGE.md)** – Detailed usage guide with examples
- **[IOC-LIST.md](docs/IOC-LIST.md)** – Complete list of indicators with threat sources
- **[CHANGELOG.md](docs/CHANGELOG.md)** – Version history and IOC updates

## Testing

Run the test suite:
```powershell
cd tests
Invoke-Pester test.ps1 -Verbose
```

Tests validate:
- Correct detection of known malicious packages
- Proper identification of suspicious lifecycle scripts
- False positive rate on clean manifests
- Transitive dependency resolution accuracy

## Requirements

- PowerShell 5.0+
- (Optional) Docker with node:20-alpine image for `-ScanTransitive` flag

## Security Considerations

- **Static Analysis Only** – No code is executed during scanning
- **Locked Container Scans** – Transitive scans run in read-only mounted containers
- **No External Dependencies** – Pure PowerShell, no external tools required
- **Offline Capable** – Works without internet (except docker image pulls for transitive scans)

## Contributing

1. Found a new malicious package? Add it to `$iocPatterns.malicious_packages` in the script
2. Have test fixtures? Submit them in `/tests/fixtures/`
3. Open an issue or PR with threat intelligence context

## License

GNU Affero General Public License v3.0 only (AGPL-3.0-only) – See [LICENSE](LICENSE) for details

## Disclaimer

This tool performs static analysis and pattern matching. It is not a substitute for:
- Code review and vetting
- Runtime security monitoring
- Regular dependency audits
- Security best practices (private registries, package signing, etc.)

Use as part of a defense-in-depth security strategy.
