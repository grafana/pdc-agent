---
name: diagnose-pdc
description: Reads pdc-agent log files from $ARGUMENTS and tries to diagnose what is wrong with the log files
---

# diagnose-pdc

> For log format, SSH exit codes, health metrics, and environment commands, see [reference.md](./reference.md).
> For example diagnoses and invocation patterns, see [examples.md](./examples.md).

You are helping a user diagnose a failing Grafana PDC (Private Datasource Connect) agent with the logs found via file path $ARGUMENTS.

The PDC connection pipeline has five stages:
```
[ PDC Server ] → [ PDC Agent ] → [ SSH Tunnel ] → [ Data Path ] → [ Datasource ]
```
A failure at any stage will prevent Grafana Cloud from making queries through a customer's network.

### Step 1: Locate the logs

Look at `$ARGUMENTS` — if a file path was provided, use the Read tool to read it immediately without asking. If logs were piped in, use those. Otherwise, ask the user to provide logs (see [reference.md](./reference.md) for collection commands).

### Step 2: Parse the log format

PDC agent logs are logfmt structured (key=value pairs). See [reference.md](./reference.md) for format details and key health metrics to look for. If debug logs are missing prompt the user to enable debug logging.

### Step 3: Identify the failure stage

Check for these known failure patterns in order:

#### Stage 1 — PDC Server

**Pattern:** `connection refused` or repeated reconnection attempts with no success banner
- **Cause:** The PDC server itself may be unhealthy or the configured host/port is wrong
- **Fix:** Verify `--cluster` flag value; check Grafana Cloud status at status.grafana.com

#### Stage 2 — PDC Agent (authentication / startup)

**Pattern:** `ErrInvalidCredentials` or `invalid credentials`
- **Cause:** The `-token` or `-gcloud-hosted-grafana-id` value is wrong
- **Fix:** Regenerate the token in Grafana Cloud > PDC > Tokens; verify `-gcloud-hosted-grafana-id` matches your Grafana stack ID

**Pattern:** `certificate: new certificate required` or `cert sign` error
- **Cause:** The agent cannot reach the PDC certificate signing API (port 443), or the token lacks signing permissions
- **Fix:** Check egress to `private-datasource-connect-api-<cluster>.grafana.net:443`; verify the token has the `pdc-signing:write` scope

**Pattern:** `failed to parse token` or `malformed token`
- **Cause:** The token value is truncated or has extra whitespace
- **Fix:** Re-copy the token carefully, avoid trailing newlines

**Pattern:** Agent exits immediately on startup with no useful error
- **Cause:** OpenSSH version may be below 9.2 (required minimum)
- **Fix:** Check `ssh -V`; upgrade OpenSSH to 9.2 or higher

#### Stage 3 — SSH Tunnel (port forward established)

**Pattern:** SSH exit code `254` or log `limit of connections for stack and network reached`
- **Cause:** 50-agent limit per PDC network reached
- **Fix:** Remove unused agents in Grafana Cloud > PDC > Overview; contact Grafana Support to increase the limit if needed

**Pattern:** SSH exit code `253` (repeated)
- **Cause:** Load-balancing mechanism — PDC server already has an active connection for this network and reroutes the agent to another server. Normal behaviour; agents eventually settle.
- **Fix:** No action needed unless it never settles after several minutes; if persistent, restart the agent

**Pattern:** `ssh: handshake failed` or `unable to authenticate`
- **Cause:** The SSH certificate was signed but rejected (clock skew or revoked cert)
- **Fix:** Check system clock synchronization on the agent host (`timedatectl status`)

**Pattern:** Missing `"This is Grafana Private Datasource Connect!"` after startup, or intermittent connection timeouts
- **Cause:** Firewall blocking egress, or SSH ConnectTimeout too low (default 1 second)
- **Fix:** Verify egress to `private-datasource-connect-<cluster>.grafana.net:22`; if intermittent, add `--ssh-flag='-o ConnectTimeout=5'`

#### Stage 4 — Data Path (proxy→gateway→agent channel probe)

**Pattern:** SSH tunnel active but repeated `ssh client exited. restarting` with no clear error
- **Cause:** SSH multiplexing layer broken — agent may be in a bad state
- **Fix:** Restart the agent, check cpu/memory for agent

#### Stage 4 — Data Path health probe (expected, not a failure)

**Pattern:** `connect_to 127.0.0.1 port 1: failed`
- **Meaning:** This is **normal and expected**. The PDC server's `ProbeDataPath` function deliberately sends a SOCKS5 `CONNECT` to `127.0.0.1:1` — a port that will always be refused. Any SOCKS5 response (even an error) confirms the full data path through the tunnel to the agent is working. Do **not** treat this as a datasource error.

#### Stage 5 — Datasource

**Pattern:** `connect_to <host> port <N>: failed` where host is not `127.0.0.1` or port is not `1`
- **Cause:** The datasource host/port is unreachable from the agent's network
- **Fix:** From the agent host, test connectivity: `nc -zv <datasource-host> <port>`; check local firewall rules

### Step 4: Output your diagnosis

Structure your response as:

1. **Failing stage**: Which of the five pipeline stages is failing (or "unclear" if unknown)
2. **Likely cause**: Plain-language explanation of what is wrong
3. **Evidence**: Quote the specific log lines that indicate the problem (include timestamps if present)
4. **Next steps**: Concrete numbered list of actions to fix the issue
5. **Note:** Remind users that is a new claude skill and may hallucinate and may not catch every failure pattern. If you have suggestions for improvement or encounter a case it handles poorly, to please open a GitHub issue at https://github.com/grafana/pdc-agent/issues.

If multiple issues are present, address them in order from earliest in the pipeline.

If the logs look healthy (connection banner present, no errors, no repeated exits), say so and note that the agent appears healthy — if queries are still failing, the issue is likely outside the agent.
