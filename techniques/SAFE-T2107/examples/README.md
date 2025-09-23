# SAFE-T2107 Examples

This directory contains working examples and demonstrations of the **SAFE-T2107: AI Model Poisoning via MCP Tool Training Data Contamination** technique discovered by Sachin Keswani.

## Overview

These examples demonstrate how attackers can poison AI model training data through MCP tool outputs, creating persistent backdoors and vulnerabilities that persist across model deployments and updates.

## Demo Scripts

### 1. `training-data-poisoning-demo.py`
A comprehensive demonstration showing:
- How to inject malicious patterns into MCP tool outputs
- How poisoned data flows through training pipelines
- How AI models learn malicious behaviors
- How backdoors are activated in production

### 2. `defense-mechanisms-demo.py`
Demonstrates the proposed defense mechanisms:
- Training data provenance verification
- AI model integrity validation
- Adversarial training data detection
- Model behavior monitoring

### 3. `working-demo.py`
A complete working demonstration that shows:
- Attack execution with realistic scenarios
- Defense mechanisms in action
- Performance comparison between attacked and defended systems
- Real-time monitoring and detection

## Quick Start

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Attack Demo**:
   ```bash
   python training-data-poisoning-demo.py
   ```

3. **Run Defense Demo**:
   ```bash
   python defense-mechanisms-demo.py
   ```

4. **Run Complete Demo**:
   ```bash
   python working-demo.py
   ```

## Key Features

- **Realistic Attack Scenarios**: Based on actual MCP tool usage patterns
- **Comprehensive Defense**: Multiple layers of protection
- **Performance Metrics**: Quantitative analysis of attack and defense effectiveness
- **Educational Content**: Clear explanations of techniques and mitigations

## Security Notice

These examples are for educational and research purposes only. They demonstrate real attack techniques that could be used maliciously. Use responsibly and only in authorized testing environments.

## Author

**Sachin Keswani** - Security Researcher
- Discovery Date: August 30, 2025
- Technique: SAFE-T2107
- Mitigations: SAFE-M-33 through SAFE-M-36
