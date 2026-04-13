# SIEM webhook token rotation runbook

**Schedule:** every 90 days, hard cutoff. Overdue = paging incident.
**Owner:** MILNET platform on-call.
**Automation:** `milnet-siem-rotate.timer` alerts when overdue. Rotation is
**manual by design** — automated rotation of an audit-tier secret would
violate two-person integrity.

## When to rotate

- 90 days after the last rotation (timestamp in
  `/var/lib/milnet/siem-rotation.stamp`).
- Immediately on any of:
  - Vault audit log entry showing access from an unrecognised principal.
  - SIEM ingestion gap > 5 minutes that does not correlate with a known
    network event.
  - Departure of any operator with prior knowledge of the token.

## Procedure

1. **Authenticate** to Vault with two operators (TOTP + hardware key).

   ```sh
   vault login -method=oidc role=milnet-rotator
   ```

2. **Mint** a new SIEM webhook token (96-byte URL-safe random):

   ```sh
   NEW_TOKEN=$(openssl rand -base64 96 | tr -d '\n=' | tr '+/' '-_')
   vault kv put secret/milnet/prod/siem \
       webhook_token="$NEW_TOKEN" \
       rotated_at="$(date -u +%FT%TZ)" \
       rotated_by="$USER"
   ```

3. **Validate** by sending a synthetic event from a staging gateway:

   ```sh
   curl --fail -sS \
       -H "Authorization: Bearer $NEW_TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"type":"rotation-test","ts":"'"$(date -u +%FT%TZ)"'"}' \
       https://siem.milnet.internal/v1/ingest
   ```

   The SIEM dashboard MUST show the `rotation-test` event within 30 seconds.

4. **Roll** all gateway/orchestrator/audit pods to pick up the new value:

   ```sh
   kubectl -n milnet rollout restart \
       deploy/gateway deploy/orchestrator deploy/audit
   kubectl -n milnet rollout status deploy/gateway --timeout=300s
   kubectl -n milnet rollout status deploy/orchestrator --timeout=300s
   kubectl -n milnet rollout status deploy/audit --timeout=300s
   ```

5. **Verify** ingestion is unbroken — query SIEM for events from the rolled
   pods within the last 60 seconds. If gap > 60 seconds, **revert**:

   ```sh
   vault kv rollback -version=-1 secret/milnet/prod/siem
   kubectl -n milnet rollout restart deploy/gateway deploy/orchestrator deploy/audit
   ```

6. **Stamp** completion on the bastion:

   ```sh
   sudo date -u +%FT%TZ > /var/lib/milnet/siem-rotation.stamp
   ```

7. **Log** the rotation in the change-control ticket. Both operators sign.

## Recovery

If rotation succeeds in Vault but pods cannot reach Vault during rollout,
they will continue to use the cached old token until ESO refreshes
(`refreshInterval: 1h`). Force a refresh:

```sh
kubectl -n milnet annotate externalsecret milnet-siem-config \
    force-sync=$(date +%s) --overwrite
```
