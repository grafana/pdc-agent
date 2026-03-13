# diagnose-pdc Examples

## Invocation Patterns

```
# With a log file path
/diagnose-pdc /var/log/pdc-agent.log

# Paste logs inline after the command
/diagnose-pdc
level=error ts=2024-01-15T10:23:45Z msg="connection failed" err="ErrInvalidCredentials"

# Pipe logs directly
journalctl -u pdc-agent -n 100 | claude /diagnose-pdc
```

---

## Example Diagnoses

### Stage 2 — Invalid credentials

**Input:**
```
level=info  ts=2024-01-15T10:23:40Z msg="starting pdc-agent" version=0.0.18
level=error ts=2024-01-15T10:23:45Z msg="failed to connect" err="ErrInvalidCredentials"
level=info  ts=2024-01-15T10:23:50Z msg="retrying in 5s"
level=error ts=2024-01-15T10:23:55Z msg="failed to connect" err="ErrInvalidCredentials"
```

**Expected output:**
> **Failing stage:** Stage 2 — PDC Agent (authentication)
>
> **Likely cause:** The token or stack ID is incorrect.
>
> **Evidence:** `err="ErrInvalidCredentials"` at 10:23:45 and 10:23:55 — repeated auth failures with no success.
>
> **Next steps:**
> 1. Regenerate the token in Grafana Cloud > Connections > Private Datasource Connect > Configuration Details
> 2. Verify `-gcloud-hosted-grafana-id` matches your Grafana stack
> 3. Re-copy the token carefully — avoid trailing newlines or extra whitespace
> 4. Verify that `-cluster` is correct as well

---

### Stage 3 — Connection limit reached

**Input:**
```
level=info  ts=2024-01-15T11:00:01Z msg="SSH connection established"
level=info  ts=2024-01-15T11:00:01Z msg="This is Grafana Private Datasource Connect!"
level=error ts=2024-01-15T11:00:03Z msg="SSH exit" code=254
level=info  ts=2024-01-15T11:00:33Z msg="retrying in 30s"
```

**Expected output:**
> **Failing stage:** Stage 3 — SSH Tunnel
>
> **Likely cause:** The connection limit for this private network has been reached.
>
> **Evidence:** SSH exit code 254 at 11:00:03 after a successful handshake.
>
> **Next steps:**
> 1. Go to Grafana Cloud > Connections > Private Datasource Connect, select your network and review connected agents
> 2. Disconnect or remove unused agents
> 3. If all connections are legitimate, contact Grafana support to increase the limit

---

### Stage 5 — Datasource unreachable

**Input:**
```
level=info msg="This is Grafana Private Datasource Connect!"
level=info msg="numAuthenticatedAgents" count=1
level=info msg="numConnectedAgents" count=1
level=error msg="connect_to postgres.internal port 5432: failed"
```

**Expected output:**
> **Failing stage:** Stage 5 — Datasource
>
> **Likely cause:** The datasource host is unreachable from the agent's network.
>
> **Evidence:** `connect_to postgres.internal port 5432: failed` — tunnel is healthy but the target is unreachable.
>
> **Next steps:**
> 1. From the agent host, test: `nc -zv postgres.internal 5432`
> 2. Check local firewall rules on the agent host
> 3. Verify the datasource hostname resolves correctly: `nslookup postgres.internal`
> 4. Verify datasource configuration details are correct (correct endpoint, correct datasource credentials if any)

---

### Healthy agent

**Input:**
```
level=info msg="starting pdc-agent" version=0.0.18
level=info msg="This is Grafana Private Datasource Connect!"
level=info msg="numAuthenticatedAgents" count=1
level=info msg="numConnectedAgents" count=1
```

**Expected output:**
> Logs look healthy. The connection banner is present and both authentication and tunnel metrics are positive.
>
> If queries are still failing in Grafana, check:
> - That the datasource is configured to use Private Datasource Connect in Grafana Cloud
> - That the datasource has the correct credentials and configuration settings
> - Check the Connections diagnostics page to make a test request through the connection to ensure the ssh tunnel is still healthy and responding
> - Check the cpu/memory of the pdc-agent
