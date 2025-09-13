# SAFE-T2106 Examples

This directory contains working examples and demonstrations of the **SAFE-T2106: Context Memory Poisoning via Vector Store Contamination** technique discovered by Sachin Keswani.

## Files

- **`vector-store-poisoning-demo.py`**: Basic demonstration of the attack technique
- **`working-demo.py`**: Complete demonstration showing both attack and defense
- **`requirements.txt`**: Python dependencies for running the demos

## Quick Start

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run basic demo**:
   ```bash
   python3 vector-store-poisoning-demo.py
   ```

3. **Run complete demo** (attack + defense):
   ```bash
   python3 working-demo.py
   ```

## What the Demos Show

### Attack Demonstration
- How attackers create poisoned embeddings
- How malicious content is stored in vector databases
- How AI agents retrieve contaminated information
- The persistence and self-replicating nature of the attack

### Defense Demonstration
- Content validation and sanitization
- Cryptographic integrity verification
- Secure vector store operations
- Multi-layered security controls

## Educational Use Only

⚠️ **WARNING**: These demos are for educational purposes only. Do not use against production systems or real AI agents.

## Requirements

- Python 3.7+
- numpy
- pyyaml (for detection rule testing)

## Output

The demos provide detailed output showing:
- Step-by-step attack execution
- Security control implementation
- Attack vs defense effectiveness comparison
- Key insights about vector store security
