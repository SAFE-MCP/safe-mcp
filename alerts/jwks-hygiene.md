# Alerts: JWKS Hygiene

- **Unknown kid deny**
  - Condition: `result == "deny_unknown_kid"` (rate > 0 for 2m)
  - Action: page on-call; create incident.

- **Stale JWKS cache**
  - Condition: `jwks_cache_age_ms > 900000` sustained 5m (per issuer)
  - Action: warn (SLO); if > 20m escalate.

- **Rotation window exceeded**
  - Condition: both old+new keys observed > 60m
  - Action: ticket + on-call notification.

- **Key age exceeds policy**
  - Condition: signer `kid` unchanged > 90d
  - Action: ticket; schedule rotation.
