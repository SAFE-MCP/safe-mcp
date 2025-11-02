# SAFE-T1915: Cross-Chain Laundering via Bridges/DEXs ("Chain-Hopping")

## Overview
**Tactic**: Exfiltration (ATK-TA0010), Defense Evasion (ATK-TA0005), Impact (ATK-TA0040)  
**Technique ID**: SAFE-T1915  
**Severity**: High  
**First Observed**: Not documented in production (technique analysis based on industry reports)  
**Last Updated**: 2025-11-02

## Description

Adversaries obscure the provenance of illicit value by **moving funds across multiple blockchains** (e.g., Ethereum → Avalanche → TRON) using **cross-chain bridges, decentralized exchanges (DEXs), swap/aggregator services, and wrapped assets**. This **"chain-hopping"** breaks simple single-chain traces and is often combined with mixers and stablecoin swaps before **cash-out at custodial off-ramps**.

This technique exploits the technical complexity of tracking assets across multiple blockchain networks with different architectures, consensus mechanisms, and transaction formats. By fragmenting transaction trails across chains, adversaries increase the difficulty and cost of forensic analysis for investigators and compliance teams.

## Attack Vectors

- **Primary Vector**: Cross-chain bridges for multi-hop asset transfers
- **Secondary Vectors**:
  - Decentralized exchanges (DEXs) for intra-chain swaps
  - Wrapped asset protocols for cross-chain value representation
  - Stablecoin pivoting (USDT/USDC/DAI) between chains
  - Custodial off-ramps and OTC services for final cash-out

## Technical Details

### Prerequisites
- Ability to **control a source wallet/key** or an MCP tool that can sign transactions
- Access to **bridge and DEX infrastructure** (public smart contracts, RPC endpoints)
- Liquidity in target assets and **available off-ramp**

### Attack Flow

1. **Placement / Initial Control**: Funds controlled on Chain A (often from a compromise, fraud, or skimming event)
2. **Swap & Fragment**: Swap into liquid/stable assets; split across fresh addresses
3. **Bridge Hop**: Use **cross-chain bridge** smart contracts to mint/burn wrapped assets and move to Chain B (sometimes repeating to Chain C)
4. **DEX Hops**: Use DEX/aggregators for intra-chain swaps; repeat bridging as needed
5. **Mixer (Optional)**: Where available, route into mixers; adapt to takedowns by switching services
6. **Off-Ramp**: Consolidate and **cash-out at custodial services/OTCs** or continue layering

### Example Scenario

```json
{
  "scenario": "Automated chain-hopping via MCP tool",
  "attack_sequence": [
    {
      "step": 1,
      "chain": "Chain A",
      "action": "swap",
      "tool_call": "crypto_wallet.swap",
      "params": {
        "from_token": "NATIVE_TOKEN",
        "to_token": "STABLECOIN",
        "amount_usd": "10000"
      }
    },
    {
      "step": 2,
      "chain": "Chain A -> Chain B",
      "action": "bridge",
      "tool_call": "cross_chain_bridge.transfer",
      "params": {
        "from_chain": "chain_a",
        "to_chain": "chain_b",
        "token": "STABLECOIN",
        "destination_address": "fresh_address_1"
      }
    },
    {
      "step": 3,
      "chain": "Chain B",
      "action": "swap",
      "tool_call": "dex_aggregator.swap",
      "params": {
        "from_token": "STABLECOIN_A",
        "to_token": "STABLECOIN_B"
      }
    },
    {
      "step": 4,
      "chain": "Chain B -> Chain C",
      "action": "bridge",
      "tool_call": "cross_chain_bridge.transfer",
      "params": {
        "from_chain": "chain_b",
        "to_chain": "chain_c",
        "token": "STABLECOIN_B",
        "destination_address": "fresh_address_2"
      }
    },
    {
      "step": 5,
      "chain": "Chain C",
      "action": "off-ramp",
      "tool_call": "exchange_deposit.send",
      "params": {
        "destination": "custodial_service",
        "token": "STABLECOIN_B",
        "memo": "deposit_identifier"
      }
    }
  ],
  "obfuscation_techniques": [
    "Multi-chain hops to break analysis",
    "Fresh addresses at each hop",
    "Stablecoin pivoting between different issuers",
    "DEX and bridge combination",
    "Custodial service deposit for cash-out"
  ]
}
```

### Advanced Attack Techniques

Observed variations of this technique include:

1. **Bi-directional Bridge Exploitation**: Attackers use both lock/mint and burn/unlock mechanisms across multiple bridge protocols to create complex transaction graphs

2. **DEX Aggregator Layering**: Using multi-hop DEX aggregators (e.g., 1inch, Paraswap) between bridge operations to further fragment the trail and exploit different liquidity pools

3. **Wrapped Asset Cycling**: Converting between different wrapped versions of the same asset (e.g., WETH, renBTC, wrapped USDC) across chains to exploit gaps in labeling and tracking

4. **Off-Ramp Concentration**: Targeting known custodial exchanges and OTC services for final cash-out operations

## Impact Assessment

- **Confidentiality**: Medium - Transaction data is public on-chain but origin/destination relationships are obfuscated
- **Integrity**: High - Legitimate transaction mechanisms are abused; trust in cross-chain infrastructure is undermined
- **Availability**: Low - Does not directly impact service availability
- **Scope**: Network-wide - Can span multiple blockchain networks and jurisdictions

### Current Status (2025)

Organizations and regulators are developing mitigations:

- **Cross-chain analytics platforms** are emerging to support bi-directional bridge tracing across multiple blockchain networks
- **FATF Targeted Updates (2024-2025)** strengthen Travel Rule requirements for Virtual Asset Service Providers (VASPs), including cross-chain operations ([FATF, 2024](https://www.fatf-gafi.org/content/dam/fatf-gafi/recommendations/2024-Targeted-Update-VA-VASP.pdf.coredownload.inline.pdf))
- **US Treasury DeFi Risk Assessment (2023)** identified chain-hopping vulnerabilities and recommended enhanced monitoring ([US Treasury, 2023](https://home.treasury.gov/system/files/136/DeFi-Risk-Full-Review.pdf))

## Detection Methods

### Indicators of Compromise (IoCs)

- Rapid sequence of bridge lock/mint/burn transactions across multiple chains
- Fresh addresses appearing immediately after bridge operations
- Repeated stablecoin swaps (USDT/USDC/DAI) surrounding bridge operations
- High-frequency use of multiple bridge protocols within short time windows
- Deposits to known high-risk custodial off-ramps following multi-hop sequences
- Transaction patterns matching known DPRK or ransomware operator TTPs

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Attackers continuously develop new chain-hopping techniques and bridge exploitation methods. Organizations should:
- Use AI-based anomaly detection to identify novel cross-chain patterns
- Regularly update detection rules based on threat intelligence
- Implement multiple layers of detection beyond pattern matching
- Consider graph analysis of cross-chain transaction flows

```yaml
title: Cross-Chain Laundering via Bridge Hopping
id: a7f8c9d2-1e4b-4a5c-9f3d-8b6e2c5a1d9f
status: experimental
description: Detects suspicious cross-chain bridge usage patterns indicative of laundering via chain-hopping
author: SAFE-MCP Contributors
date: 2025-11-02
references:
  - https://github.com/SAFE-MCP/safe-mcp/techniques/SAFE-T1915
  - https://www.chainalysis.com/blog/2024-crypto-money-laundering/
  - https://www.elliptic.co/hubfs/The%20state%20of%20cross-chain%20crime%202025/The%20state%20of%20cross-chain%20crime%202025%20-%20FINAL.pdf
logsource:
  product: mcp
  service: blockchain_tools
detection:
  bridge_sequence:
    tool_name:
      - 'cross_chain_bridge.*'
      - 'bridge.transfer'
      - 'multichain.*'
    action: 'transfer'
  timeframe: 1h
  condition: bridge_sequence | count(distinct_chains) >= 3
falsepositives:
  - Legitimate cross-chain arbitrage trading
  - Market maker operations across multiple chains
  - Multi-chain treasury management for DeFi protocols
level: high
tags:
  - attack.exfiltration
  - attack.defense_evasion
  - attack.ta0010
  - attack.ta0005
  - safe.t1915
```

### Behavioral Indicators

- Unusual bridge protocol diversity (using 3+ different bridges in short succession)
- Fresh wallet addresses created immediately after each bridge operation
- Stablecoin-only operations (avoiding native chain tokens)
- Off-ramp deposits that match the timing and amount of prior bridge sequences
- Geographic clustering of off-ramp services in jurisdictions with weak AML enforcement
- Repeated patterns matching known threat actor methodologies (e.g., Lazarus Group TTPs)

## Mitigation Strategies

### Preventive Controls

1. **[SAFE-M-1: Input Validation](../../mitigations/SAFE-M-1/README.md)**: Validate all blockchain transaction parameters and enforce allowlists for approved bridge protocols and destination chains
2. **[SAFE-M-8: Rate Limiting](../../mitigations/SAFE-M-8/README.md)**: Implement velocity limits on cross-chain bridge operations per session/user
3. **[SAFE-M-19: Least Privilege](../../mitigations/SAFE-M-19/README.md)**: Restrict MCP tool capabilities for blockchain operations; require explicit user consent for cross-chain transfers
4. **Bridge Risk Management**: Maintain an updated list of high-risk bridge protocols and off-ramp services; block or require enhanced review for suspicious routes

### Detective Controls

1. **[SAFE-M-2: Comprehensive Logging](../../mitigations/SAFE-M-2/README.md)**: Log all bridge transactions with full cross-chain context including source chain, destination chain, bridge protocol, amounts, and addresses
2. **[SAFE-M-10: Anomaly Detection](../../mitigations/SAFE-M-10/README.md)**: Deploy AI-based anomaly detection for unusual multi-chain patterns and rapid bridge sequences
3. **Transaction Graph Analysis**: Implement bi-directional cross-chain tracing to link lock/mint/burn events across blockchain networks
4. **Custodial Off-Ramp Monitoring**: Prioritize monitoring of known custodial services that historically receive concentrated illicit inflows

### Response Procedures

1. **Immediate Actions**:
   - Freeze suspicious wallet operations pending investigation
   - Notify compliance team for SAR preparation
   - Document full cross-chain transaction trail
   - Check against sanctions lists (OFAC SDN, UN, EU)

2. **Investigation Steps**:
   - Reconstruct complete chain-hopping sequence across all blockchains
   - Identify all intermediate addresses and bridge protocols used
   - Correlate with known threat actor TTPs (e.g., DPRK Lazarus Group patterns)
   - Analyze off-ramp destinations and beneficiary services
   - Cross-reference with industry threat intelligence feeds

3. **Remediation**:
   - File Suspicious Activity Report (SAR) following FinCEN guidance
   - Update bridge protocol and off-ramp risk scoring
   - Enhance detection rules based on observed TTPs
   - Coordinate with law enforcement if sanctions violations identified
   - Implement additional controls for high-risk chains/bridges

## Related Techniques

- **SAFE-T1910**: Covert Channel Exfiltration - Chain-hopping extends covert exfiltration to blockchain value transfers
- **SAFE-T1911**: Parameter Exfiltration - Bridge parameters can be used to encode additional data
- **SAFE-T1913**: HTTP POST Exfil - Off-ramp deposits often use HTTP APIs
- **SAFE-T1914**: Tool-to-Tool Exfil - Chain-hopping inherently chains multiple blockchain tools
- **SAFE-T2104**: Fraudulent Transactions - Chain-hopping is often used to launder proceeds from fraudulent on-chain transactions

## References

- [SAFE-MCP Repository - TTP Table](https://github.com/SAFE-MCP/safe-mcp)
- [US Treasury - Illicit Finance Risk Assessment of DeFi](https://home.treasury.gov/system/files/136/DeFi-Risk-Full-Review.pdf)
- [FATF - 2024 Targeted Update on Virtual Assets and VASPs](https://www.fatf-gafi.org/content/dam/fatf-gafi/recommendations/2024-Targeted-Update-VA-VASP.pdf.coredownload.inline.pdf)
- [FinCEN - SAR Electronic Filing Instructions](https://www.fincen.gov/system/files/shared/FinCEN%20SAR%20ElectronicFilingInstructions-%20Stand%20Alone%20doc.pdf)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)

## MITRE ATT&CK Mapping

- [TA0010 - Exfiltration](https://attack.mitre.org/tactics/TA0010/) (Primary)
- [TA0005 - Defense Evasion](https://attack.mitre.org/tactics/TA0005/) (Secondary)
- [TA0040 - Impact](https://attack.mitre.org/tactics/TA0040/) (When used with fraudulent transactions)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-02 | Initial documentation | Laxmi Pant |

