# ZeroTrace Architecture

## Overview

ZeroTrace is a dependency-free security scanner designed to detect
potentially exposed secrets and credentials inside source-code repositories.

## Goals

- Scan files recursively
- Detect potential secrets
- Calculate confidence/risk scores
- Report findings with file and line information
- Work without third-party runtime dependencies
- Provide useful CLI output

## Detection Pipeline

Files
→ Content Reader
→ Pattern Detection
→ Entropy Analysis
→ Context Analysis
→ Risk Scoring
→ Reporter

## Planned Components

### File Scanner

Responsible for recursively discovering files and filtering files that
should not be scanned.

### Content Reader

Responsible for reading files safely and providing line information.

### Detection Engine

Responsible for identifying potential secrets.

### Pattern Detector

Detects known credential patterns.

### Entropy Analyzer

Detects high-entropy strings that may represent randomly generated secrets.

### Risk Scorer

Combines multiple signals to determine the severity of a finding.

### Reporter

Displays findings in human-readable and machine-readable formats.

### CLI

Provides commands and options for users to operate ZeroTrace.

## Future Features

- Baseline support
- Finding comparison
- Multithreaded scanning
- JSON output
- Ignore rules
- Configurable detection rules
- Benchmarking