# SAFE-T1304: Credential Relay Chain - Example Implementation

## Overview

This directory contains working examples demonstrating **SAFE-T1304: Credential Relay Chain** detection and attack simulation. These examples are generated from `pseudocode.md` and `detection-rule.yml`.

## Technique Description



## Files

- **`detector.py`**: Detection implementation based on `detection-rule.yml`
- **`attack_simulation.py`**: Attack simulation based on `pseudocode.md`
- **`EXAMPLE.md`**: This file - documentation of the technique and validation

## Source Files

- **`../pseudocode.md`**: Attack flow pseudocode ✓
- **`../detection-rule.yml`**: Sigma detection rule ✓
- **`../README.md`**: Complete technique documentation

## Detection Implementation

The detector (`detector.py`) implements patterns from the Sigma detection rule to identify credential relay chain indicators in MCP environments.

### Key Features

- Pattern matching based on detection-rule.yml
- Log file analysis
- Report generation with severity levels

## Attack Simulation

The attack simulation (`attack_simulation.py`) demonstrates the attack flow as documented in `pseudocode.md`.

### Running the Simulation

```bash
python3 attack_simulation.py
```

This will generate attack logs that can be used to test the detector.

## Testing Detection

### 1. Generate Attack Logs

```bash
python3 attack_simulation.py
```

### 2. Test Detection

```bash
python3 detector.py safe-t1304_attack_logs.json
```

## Validation

These examples should be validated against:
- The pseudocode in `../pseudocode.md`
- The detection patterns in `../detection-rule.yml`
- The test cases in `../test_detection_rule.py` (if available)

## Limitations

1. **Coverage**: Examples may not cover all attack variations
2. **False Positives**: Legitimate activities may trigger alerts
3. **Evasion**: Sophisticated attackers may use evasion techniques

## References

- See `../README.md` for complete technique documentation
- See `../detection-rule.yml` for Sigma detection rule
- See `../pseudocode.md` for attack flow pseudocode
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)

## Educational Use Only

⚠️ **WARNING**: These examples are for educational and defensive purposes only. Do not use these techniques against production systems or real MCP deployments.
