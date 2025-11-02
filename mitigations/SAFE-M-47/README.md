# SAFE-M-47: Cross-Chain Transaction Graph Analysis

## Overview

**Mitigation ID**: SAFE-M-47  
**Category**: Detective Control  
**Effectiveness**: High  
**Implementation Complexity**: High  
**First Published**: 2025-11-02

## Description

Cross-Chain Transaction Graph Analysis implements bi-directional tracing capabilities to link blockchain transactions across multiple chains, specifically tracking lock/mint/burn events through bridge protocols. This mitigation reconstructs complete transaction flows across chain boundaries to identify money laundering patterns and fund provenance.

## Mitigates

- [SAFE-T1915](../../techniques/SAFE-T1915/README.md): Cross-Chain Laundering via Bridges/DEXs

## Technical Implementation

### Core Components

1. **Multi-Chain Transaction Indexer**
   - Index transactions from multiple blockchain networks
   - Track cross-chain bridge events (lock, mint, burn, unlock)
   - Maintain unified address mapping across chains
   - Real-time and historical transaction analysis

2. **Bridge Event Correlation**
   - Link source chain lock events with destination chain mint events
   - Track burn events and corresponding unlock operations
   - Identify intermediate addresses in multi-hop sequences
   - Detect timing patterns and transaction clustering

3. **Graph Database Architecture**
   - Store cross-chain relationships in graph structure
   - Model addresses, transactions, and chains as nodes
   - Model transfers, bridges, and swaps as edges
   - Enable complex path queries across chains

4. **Pattern Detection Algorithms**
   - Identify rapid chain-hopping sequences
   - Detect circular flows (funds returning to origin)
   - Find split/merge patterns across chains
   - Calculate risk scores based on graph topology

### Implementation Steps

1. **Setup Multi-Chain Indexing**
   ```python
   # Configure blockchain data sources
   chain_configs = {
       "ethereum": {
           "rpc_endpoint": "https://eth-mainnet.g.alchemy.com/v2/...",
           "start_block": 18000000,
           "bridge_contracts": [
               "0x...",  # Stargate Router
               "0x...",  # Hop Protocol
           ]
       },
       "polygon": {
           "rpc_endpoint": "https://polygon-mainnet.g.alchemy.com/v2/...",
           "start_block": 45000000,
           "bridge_contracts": ["0x..."]
       }
   }
   ```

2. **Build Graph Schema**
   ```python
   # Neo4j/Graph database schema
   class Address(Node):
       chain = StringProperty()
       address = StringProperty()
       first_seen = DateTimeProperty()
       labels = ArrayProperty()  # e.g., ["exchange", "mixer"]
   
   class Transaction(Node):
       chain = StringProperty()
       tx_hash = StringProperty()
       timestamp = DateTimeProperty()
       amount = FloatProperty()
       token = StringProperty()
   
   class BridgeTransfer(Relationship):
       bridge_protocol = StringProperty()
       source_chain = StringProperty()
       dest_chain = StringProperty()
       lock_tx = StringProperty()
       mint_tx = StringProperty()
       amount = FloatProperty()
       token = StringProperty()
   ```

3. **Implement Cross-Chain Tracing**
   ```python
   def trace_cross_chain_flow(start_address: str, start_chain: str, 
                              max_hops: int = 10) -> dict:
       """
       Trace fund flow across multiple blockchain networks
       """
       graph = []
       visited = set()
       queue = [(start_address, start_chain, 0)]
       
       while queue and len(graph) < max_hops:
           address, chain, depth = queue.pop(0)
           
           if (address, chain) in visited:
               continue
           visited.add((address, chain))
           
           # Find outgoing transactions on this chain
           txs = get_transactions(address, chain)
           
           # Check for bridge operations
           for tx in txs:
               bridge_event = detect_bridge_operation(tx)
               if bridge_event:
                   dest_address = bridge_event["dest_address"]
                   dest_chain = bridge_event["dest_chain"]
                   
                   graph.append({
                       "source": (address, chain),
                       "dest": (dest_address, dest_chain),
                       "bridge": bridge_event["protocol"],
                       "amount": bridge_event["amount"],
                       "tx_hash": tx["hash"]
                   })
                   
                   queue.append((dest_address, dest_chain, depth + 1))
       
       return {
           "graph": graph,
           "total_hops": len(graph),
           "chains_used": len(set(edge["dest"][1] for edge in graph)),
           "risk_score": calculate_risk_score(graph)
       }
   ```

4. **Deploy Pattern Detection**
   ```cypher
   // Cypher query to detect rapid chain-hopping
   MATCH path = (start:Address)-[r:BRIDGE_TRANSFER*3..10]->(end:Address)
   WHERE ALL(rel IN relationships(path) WHERE 
             rel.timestamp > datetime() - duration({hours: 24}))
   AND length([n IN nodes(path) | n.chain]) = length(DISTINCT [n IN nodes(path) | n.chain])
   WITH path, [n IN nodes(path) | n.chain] as chains
   WHERE size(chains) >= 3
   RETURN path, chains, 
          relationships(path)[0].amount as initial_amount,
          relationships(path)[-1].amount as final_amount
   ```

### Detection Logic

```python
def analyze_cross_chain_pattern(transaction_graph: dict) -> dict:
    """
    Analyze cross-chain transaction pattern for laundering indicators
    """
    risk_indicators = []
    risk_score = 0
    
    # Check number of chains used
    unique_chains = set()
    for edge in transaction_graph["graph"]:
        unique_chains.add(edge["source"][1])
        unique_chains.add(edge["dest"][1])
    
    if len(unique_chains) >= 3:
        risk_score += 30
        risk_indicators.append(f"Chain-hopping across {len(unique_chains)} chains")
    
    # Check for rapid sequencing
    timestamps = [edge.get("timestamp") for edge in transaction_graph["graph"]]
    if timestamps and max(timestamps) - min(timestamps) < 3600:  # 1 hour
        risk_score += 25
        risk_indicators.append("Rapid bridge sequence within 1 hour")
    
    # Check for fresh addresses
    new_addresses = sum(1 for edge in transaction_graph["graph"] 
                       if is_fresh_address(edge["dest"][0], edge["dest"][1]))
    if new_addresses / len(transaction_graph["graph"]) > 0.7:
        risk_score += 20
        risk_indicators.append(f"{new_addresses} fresh addresses in chain")
    
    # Check for stablecoin pivoting
    tokens_used = [edge.get("token") for edge in transaction_graph["graph"]]
    stablecoins = ["USDT", "USDC", "DAI", "BUSD"]
    if sum(1 for token in tokens_used if token in stablecoins) >= 2:
        risk_score += 15
        risk_indicators.append("Multiple stablecoin conversions detected")
    
    return {
        "risk_score": min(risk_score, 100),
        "risk_level": "high" if risk_score >= 70 else "medium" if risk_score >= 40 else "low",
        "indicators": risk_indicators,
        "chains_traversed": len(unique_chains),
        "total_hops": len(transaction_graph["graph"])
    }
```

## Effectiveness Assessment

### Strengths
- Reveals hidden connections across blockchain networks
- Detects complex multi-chain laundering patterns
- Provides evidence for investigations and compliance
- Scales to handle high transaction volumes

### Limitations
- Requires significant computational resources
- Depends on accurate bridge event detection
- Privacy-preserving techniques can obscure relationships
- Limited to on-chain data (off-chain activities invisible)

### Metrics
- **Coverage**: Percentage of bridge protocols tracked
- **Latency**: Time from transaction to graph update
- **Accuracy**: False positive rate for risk flagging
- **Depth**: Average number of hops successfully traced

## Integration with Other Mitigations

- **[SAFE-M-2: Comprehensive Logging](../SAFE-M-2/README.md)**: Logs provide data for graph analysis
- **[SAFE-M-10: Anomaly Detection](../SAFE-M-10/README.md)**: Graph patterns feed into anomaly detection
- **[SAFE-M-46: Bridge Risk Management](../SAFE-M-46/README.md)**: Risk scores inform bridge allowlisting
- **[SAFE-M-48: Custodial Off-Ramp Monitoring](../SAFE-M-48/README.md)**: Graph analysis identifies off-ramp destinations

## References

- [Chainalysis - Cryptocurrency Crime Report](https://www.chainalysis.com/blog/2024-crypto-crime-report-introduction/)
- [TRM Labs - Cross-Chain Investigation Techniques](https://www.trmlabs.com/)
- [Elliptic - Cross-Chain Crime and Security](https://www.elliptic.co/)
- [Neo4j Graph Database for Blockchain Analysis](https://neo4j.com/use-cases/blockchain-analytics/)

## Version History

| Version | Date       | Changes               | Author     |
|---------|------------|-----------------------|------------|
| 1.0     | 2025-11-02 | Initial documentation | Laxmi Pant |

