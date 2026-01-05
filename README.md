# Validoon

Local decision engine for security signal classification.

## What it does
Validoon analyzes raw inputs (URLs, logs, SQL fragments, encoded strings) and produces a local-only decision:
- ALLOW
- WARN
- BLOCK

Each decision includes:
- Severity score
- Confidence level
- Entropy indicator

## Key principles
- 100% local processing
- No uploads
- No network calls
- No tracking scripts

## Use cases
- Security triage
- SOC preprocessing
- Suspicious input analysis
- Offline validation

## Status
Production release – stable build.
