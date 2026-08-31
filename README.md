# ZeroTrace

A dependency-free local secret detection and security scanning engine built from scratch using C++17.

## About

ZeroTrace is a lightweight security scanning tool designed to detect hardcoded secrets and sensitive credentials inside source code and configuration files.

It scans a directory recursively, applies built-in and custom detection rules, calculates entropy and confidence, classifies findings by severity, and produces multiple report formats.

ZeroTrace is designed to work locally without third-party runtime dependencies.

## Features

- Recursive directory scanning
- Multithreaded scanning
- Configurable worker threads
- `.zerotraceignore` support
- Built-in secret detection rules
- Custom detection rules
- Rule enable/disable configuration
- Entropy analysis
- Confidence scoring
- Severity classification
- Secret redaction
- Allowlist support
- Baseline support
- JSON reporting
- SARIF 2.1.0 reporting
- HTML security dashboard
- Search and filtering in HTML reports
- Scan statistics
- Scan timing
- CI-friendly exit codes
- C++17 standard library implementation
- Zero third-party runtime dependencies

## Detection Rules

ZeroTrace currently includes detection rules for:

- Generic API Key
- Generic API Token
- Secret Key
- Password
- Credential
- AWS Access Key
- GitHub Token
- JWT
- Private Key
- Internal Token

Detection rules can be enabled or disabled through `rules.conf`.

## Severity

ZeroTrace calculates confidence and maps findings to severity levels.

| Confidence | Severity |
|------------|----------|
| 90-100% | CRITICAL |
| 75-89% | HIGH |
| 50-74% | MEDIUM |
| Below 50% | LOW |

Entropy is also calculated for detected values and can increase the confidence of a finding.

## Secret Redaction

ZeroTrace never displays detected secrets in full in its reports.

Example:

```text
AKIA1234567890EXAMPLE