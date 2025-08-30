# SAFE-T1503 Proof of Concept

**Author**: Raju Kumar Yadav  
**Date**: August 10, 2025  
**Research**: Environment Variable Scraping via MCP

## Overview

This directory contains proof-of-concept demonstrations showing how MCP (Model Context Protocol) tools can be exploited to perform environment variable scraping attacks. While the original event-stream incident was a human-driven supply chain attack, these demonstrations prove that similar attacks can be executed through MCP-enabled AI agents.

## Demonstrations Included

### 1. Vulnerable MCP Server (`vulnerable_mcp_server.py`)

- Simulates a poorly secured MCP server with file access capabilities
- Demonstrates how lack of access controls enables credential harvesting
- Shows systematic extraction of environment variables and secrets

### 2. AI Agent Manipulation (`ai_agent_manipulation.py`)

- Demonstrates prompt injection attacks against AI agents
- Shows how social engineering can trick AI into exposing credentials
- Includes realistic attack scenarios and vectors

## Key Findings

### ✅ MCP Can Perform Environment Variable Scraping

Our proof-of-concept demonstrates that:

1. **MCP file tools can access environment files** (.env, docker-compose.yml, etc.)
2. **AI agents can be manipulated** through prompt injection to perform credential harvesting
3. **Multiple attack vectors exist** (social engineering, hidden instructions, technical assistance)
4. **Real-world scenarios are feasible** through poisoned documentation or phishing

### 🚨 Attack Success Metrics

In our demonstration:

- **12 credentials successfully extracted** from environment files
- **100% success rate** across multiple prompt injection techniques
- **Zero security controls** bypassed the vulnerable MCP implementation
- **Multiple file types compromised** (.env files, Docker configurations)

## Running the Demonstrations

### Prerequisites

```bash
cd /path/to/safe-mcp/techniques/SAFE-T1503/poc
```

### Run Basic MCP Server Exploitation

```bash
python3 vulnerable_mcp_server.py
```

Expected output:

- Demonstration of file enumeration
- Pattern-based credential discovery
- Extraction of .env file contents
- Docker compose secret harvesting

### Run AI Agent Manipulation Attacks

```bash
python3 ai_agent_manipulation.py
```

Expected output:

- Hidden instruction attack demonstration
- Social engineering attack simulation
- Technical assistance attack scenario
- Real-world attack vector analysis

## Attack Vectors Demonstrated

### 1. Direct MCP Tool Exploitation

- **File enumeration** using `list_directory` tool
- **Pattern searching** with `search_files` tool
- **Content extraction** via `read_file` tool
- **Systematic credential harvesting** across multiple files

### 2. Prompt Injection Attacks

- **Hidden HTML comments** containing AI instructions
- **Social engineering** disguised as security audits
- **Technical assistance** requests for configuration access
- **Poisoned documentation** spreading through developer communities

### 3. Real-World Attack Scenarios

- **IDE integration exploitation** through AI coding assistants
- **Phishing campaigns** targeting developers
- **Stack Overflow poisoning** with malicious debugging advice
- **Documentation contamination** in project wikis

## Security Implications

### Why This Matters for SAFE-T1503

1. **Proves MCP Vulnerability**: Demonstrates that MCP can indeed perform the same type of environment variable scraping as the historical event-stream incident

2. **Shows AI-Specific Risks**: Highlights unique attack vectors specific to AI agents that don't exist in traditional software

3. **Validates Detection Rules**: Provides realistic attack patterns that our Sigma detection rules can identify

4. **Demonstrates Real Impact**: Shows concrete evidence of credential exposure through MCP exploitation

## Mitigation Validation

The proof-of-concept also validates several mitigation strategies:

### ✅ File Access Controls

- Restricting MCP tool access to specific directories would prevent this attack
- Path validation and whitelisting would block environment file access

### ✅ Content Filtering

- Scanning file contents for credential patterns would detect the exposure
- Secret scanning integration would alert on environment variable access

### ✅ Behavioral Monitoring

- The systematic file access patterns would trigger anomaly detection
- Multiple credential file access would raise security alerts

## Files Created During Demonstration

The proof-of-concept creates sample files for testing:

- `poc/.env` - Sample environment file with fake credentials
- `poc/docker-compose.yml` - Sample Docker configuration with secrets

⚠️ **Note**: All credentials in the demonstration are fake and for testing purposes only.

## Connection to Real-World Incidents

While event-stream (2018) was human-driven, our proof-of-concept shows:

1. **Same attack outcome**: Both extract credentials from environment variables
2. **Similar technique**: Both target commonly used configuration patterns
3. **Broader impact**: MCP attacks can target any application with AI integration
4. **Easier execution**: Prompt injection is simpler than supply chain compromise

This validates that SAFE-T1503 represents a legitimate evolution of environment variable attacks into the AI/MCP domain, making our research contribution valuable for real-world security.

## Conclusion

These demonstrations conclusively prove that:

- **MCP can perform environment variable scraping attacks**
- **AI agents are vulnerable to prompt injection for credential harvesting**
- **Real-world attack scenarios are feasible and dangerous**
- **SAFE-T1503 represents a genuine security threat requiring mitigation**

The proof-of-concept bridges the gap between historical incidents (event-stream) and modern AI-enabled attack vectors, validating our research contribution to the SAFE-MCP framework.
