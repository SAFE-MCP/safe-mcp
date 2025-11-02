# SAFE-M-48: Custodial Off-Ramp Monitoring

## Overview

**Mitigation ID**: SAFE-M-48  
**Category**: Detective Control  
**Effectiveness**: Medium-High  
**Implementation Complexity**: Medium  
**First Published**: 2025-11-02

## Description

Custodial Off-Ramp Monitoring prioritizes surveillance of known custodial exchanges and OTC services that historically receive concentrated illicit fund inflows following cross-chain laundering operations. This mitigation focuses detection resources on the most likely exit points where criminals convert cryptocurrency to fiat currency.

## Mitigates

- [SAFE-T1915](../../techniques/SAFE-T1915/README.md): Cross-Chain Laundering via Bridges/DEXs

## Technical Implementation

### Core Components

1. **Off-Ramp Registry**
   - Maintain list of known custodial exchanges and OTC desks
   - Track deposit addresses for each service
   - Monitor reputation and regulatory compliance status
   - Flag services with history of illicit fund reception

2. **Enhanced Monitoring Rules**
   - Real-time alerting for deposits to high-risk off-ramps
   - Lower detection thresholds for flagged services
   - Velocity tracking for deposit patterns
   - Cross-reference with bridge operation patterns

3. **Risk Scoring Framework**
   - History of sanctions violations or regulatory actions
   - KYC/AML policy strength and enforcement
   - Geographic jurisdiction and regulatory oversight
   - Volume of illicit funds historically received
   - Response to law enforcement requests

4. **Integration with Transaction Graphs**
   - Correlate off-ramp deposits with upstream bridge activity
   - Identify wallets that bridge then immediately deposit
   - Track multi-hop paths terminating at off-ramps
   - Calculate risk scores based on full transaction history

### Implementation Steps

1. **Build Off-Ramp Registry**
   ```yaml
   offramp_registry:
     - name: "Exchange A"
       type: "centralized_exchange"
       risk_level: "high"  # high, medium, low
       jurisdiction: "offshore"
       kyc_strength: "weak"
       known_addresses:
         ethereum: ["0x...", "0x..."]
         bitcoin: ["bc1...", "1..."]
       monitoring_priority: 1  # 1=highest
       notes: "Historical sanctions violations"
     
     - name: "OTC Desk B"
       type: "otc_service"
       risk_level: "medium"
       jurisdiction: "regulated"
       kyc_strength: "strong"
       monitoring_priority: 2
   ```

2. **Configure Detection Rules**
   ```python
   def evaluate_offramp_deposit(address: str, chain: str, 
                               amount: float, token: str) -> dict:
       """
       Evaluate risk of deposit to custodial off-ramp
       """
       offramp = identify_offramp(address, chain)
       
       if not offramp:
           return {"risk_level": "low", "monitored": False}
       
       risk_score = 0
       alerts = []
       
       # Base risk from off-ramp reputation
       if offramp["risk_level"] == "high":
           risk_score += 40
           alerts.append(f"Deposit to high-risk off-ramp: {offramp['name']}")
       elif offramp["risk_level"] == "medium":
           risk_score += 20
       
       # Check for recent bridge activity
       recent_bridges = check_recent_bridge_activity(address, chain, hours=24)
       if recent_bridges:
           risk_score += 30
           alerts.append(f"Recent bridge activity detected: {len(recent_bridges)} operations")
       
       # Check for fresh address
       if is_fresh_address(address, chain, max_age_minutes=60):
           risk_score += 20
           alerts.append("Deposit from fresh address (<1hr old)")
       
       # Check amount against thresholds
       if amount > 10000:
           risk_score += 10
           alerts.append(f"Large deposit amount: ${amount:,.2f}")
       
       return {
           "risk_score": min(risk_score, 100),
           "risk_level": "high" if risk_score >= 70 else "medium" if risk_score >= 40 else "low",
           "offramp": offramp["name"],
           "offramp_type": offramp["type"],
           "alerts": alerts,
           "requires_review": risk_score >= 70
       }
   ```

3. **Implement Address Clustering**
   ```python
   def cluster_offramp_addresses(offramp_name: str) -> dict:
       """
       Identify and cluster all addresses associated with an off-ramp
       """
       # Start with known addresses
       known_addresses = get_offramp_known_addresses(offramp_name)
       
       # Use heuristics to identify additional addresses
       # - Common input ownership
       # - Address reuse patterns
       # - Peel chain detection
       
       clusters = perform_address_clustering(known_addresses)
       
       return {
           "offramp": offramp_name,
           "total_addresses": len(clusters["all_addresses"]),
           "confidence": clusters["confidence_score"],
           "chains": list(clusters["chains"])
       }
   ```

4. **Deploy Real-Time Monitoring**
   ```python
   def monitor_offramp_transactions(stream):
       """
       Real-time monitoring of transactions to off-ramps
       """
       for tx in stream:
           # Check if destination is known off-ramp
           if is_offramp_address(tx["to"], tx["chain"]):
               risk_eval = evaluate_offramp_deposit(
                   tx["from"], 
                   tx["chain"],
                   tx["amount"],
                   tx["token"]
               )
               
               if risk_eval["risk_level"] in ["high", "medium"]:
                   # Generate alert
                   alert = {
                       "timestamp": tx["timestamp"],
                       "tx_hash": tx["hash"],
                       "chain": tx["chain"],
                       "from": tx["from"],
                       "to": tx["to"],
                       "amount": tx["amount"],
                       "risk_score": risk_eval["risk_score"],
                       "offramp": risk_eval["offramp"],
                       "alerts": risk_eval["alerts"]
                   }
                   
                   send_alert(alert)
                   log_suspicious_activity(alert)
                   
                   if risk_eval["requires_review"]:
                       escalate_to_compliance(alert)
   ```

### Detection Logic

```python
def analyze_offramp_pattern(wallet_address: str, chain: str, 
                           lookback_hours: int = 48) -> dict:
    """
    Analyze wallet's pattern of activity leading to off-ramp deposit
    """
    # Get transaction history
    txs = get_transaction_history(wallet_address, chain, lookback_hours)
    
    pattern_indicators = []
    risk_score = 0
    
    # Check for bridge operations
    bridge_txs = [tx for tx in txs if is_bridge_operation(tx)]
    if bridge_txs:
        risk_score += 25
        pattern_indicators.append(f"Used {len(bridge_txs)} bridge operations")
    
    # Check for DEX swaps (especially stablecoins)
    dex_swaps = [tx for tx in txs if is_dex_swap(tx)]
    stablecoin_swaps = [tx for tx in dex_swaps if involves_stablecoin(tx)]
    if len(stablecoin_swaps) >= 2:
        risk_score += 20
        pattern_indicators.append("Multiple stablecoin swaps")
    
    # Check wallet age
    wallet_age = get_wallet_age(wallet_address, chain)
    if wallet_age < 86400:  # Less than 24 hours
        risk_score += 30
        pattern_indicators.append(f"Fresh wallet (age: {wallet_age/3600:.1f}h)")
    
    # Check for mixing service usage
    if used_mixer(wallet_address, chain, txs):
        risk_score += 35
        pattern_indicators.append("Mixing service detected in history")
    
    # Check for multi-chain activity
    cross_chain_activity = get_cross_chain_activity(wallet_address)
    if len(cross_chain_activity) >= 3:
        risk_score += 20
        pattern_indicators.append(f"Multi-chain activity: {len(cross_chain_activity)} chains")
    
    return {
        "risk_score": min(risk_score, 100),
        "risk_level": "high" if risk_score >= 70 else "medium" if risk_score >= 40 else "low",
        "pattern_indicators": pattern_indicators,
        "bridge_operations": len(bridge_txs),
        "dex_swaps": len(dex_swaps),
        "wallet_age_hours": wallet_age / 3600
    }
```

## Effectiveness Assessment

### Strengths
- Focuses resources on highest-probability exit points
- Enables early detection before fiat conversion
- Supports KYC/AML compliance requirements
- Provides actionable intelligence for investigations

### Limitations
- Relies on maintaining accurate off-ramp registry
- Cannot detect off-chain or peer-to-peer exchanges
- May miss emerging or unknown off-ramp services
- False positives from legitimate users

### Metrics
- **Coverage**: Percentage of known off-ramps monitored
- **Detection Rate**: Percentage of illicit deposits flagged
- **Response Time**: Time from deposit to alert generation
- **False Positive Rate**: Legitimate transactions incorrectly flagged

## Integration with Other Mitigations

- **[SAFE-M-2: Comprehensive Logging](../SAFE-M-2/README.md)**: Logs all off-ramp deposits for analysis
- **[SAFE-M-10: Anomaly Detection](../SAFE-M-10/README.md)**: Detects unusual off-ramp deposit patterns
- **[SAFE-M-46: Bridge Risk Management](../SAFE-M-46/README.md)**: Correlates bridge usage with off-ramp deposits
- **[SAFE-M-47: Cross-Chain Transaction Graph Analysis](../SAFE-M-47/README.md)**: Provides full transaction context for off-ramp deposits

## References

- [Financial Crimes Enforcement Network (FinCEN) - Virtual Currency Guidance](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-certain-business-models)
- [FATF - Virtual Assets and Virtual Asset Service Providers (2024)](https://www.fatf-gafi.org/content/dam/fatf-gafi/recommendations/2024-Targeted-Update-VA-VASP.pdf.coredownload.inline.pdf)
- [Chainalysis - Crypto Money Laundering Flows](https://www.chainalysis.com/)
- [US Treasury - DeFi Risk Assessment (2023)](https://home.treasury.gov/system/files/136/DeFi-Risk-Full-Review.pdf)

## Version History

| Version | Date       | Changes               | Author     |
|---------|------------|-----------------------|------------|
| 1.0     | 2025-11-02 | Initial documentation | Laxmi Pant |

