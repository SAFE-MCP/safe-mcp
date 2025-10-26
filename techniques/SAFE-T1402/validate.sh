#!/usr/bin/env bash

echo "Running Sigma rule validation for SAFE-T1402..."

# Convert test logs to line-delimited JSON if needed
cat test-logs.json | jq -c '.[]' | while read -r line; do
  desc=$(echo "$line" | jq -r '.metadata.description')

  if [[ "$desc" =~ $'\u200B' ]] || [[ "$desc" =~ $'\u202D' ]] || [[ "$desc" == *"<!--"* ]] || [[ "$desc" == *"::"* ]]; then
    echo "[ALERT] Suspicious metadata detected:"
    echo "$line" | jq
  fi
done

echo "Validation complete."
