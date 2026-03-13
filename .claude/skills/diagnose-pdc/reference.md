# PDC Agent Reference

## Architecture

PDC has two planes:

**Control plane** (startup / cert signing):
- **API**: Signs the agent's public key → short-lived SSH certificate used to connect. Also serves PDC Plugin endpoints.
- **Auth Gateway (cloud-backend-gateway)**: Authenticates requests before they reach the API; appends orgID and Access Policy ID.
- **PDC Plugin**: Customer-facing UI at Menu > Connections > Private Data Source Connect.

**Data plane** (query path):
```
[ PDC Server ] → [ PDC Agent ] → [ SSH Tunnel ] → [ Data Path ] → [ Datasource ]
```

## Prerequisites

- **OpenSSH 9.2 or higher** must be installed on the host running the PDC agent
- Agent host needs **internet egress** to:
  - `private-datasource-connect-<cluster>.grafana.net:22` (SSH tunnel)
  - `private-datasource-connect-api-<cluster>.grafana.net:443` (cert signing)
  - For AWS SigV4 datasources: `sts.<region>.amazonaws.com:443`
- The `<cluster>` value is shown in Grafana under Connections > Private data source connections > Configuration Details

## Log Format

PDC agent logs are logfmt structured — key=value pairs per line:
```
level=error ts=2024-01-15T10:23:45Z msg="connection failed" err="ErrInvalidCredentials"
```

## Key Log Messages

| Message | Meaning |
|---------|---------|
| `This is Grafana Private Datasource Connect!` | SSH connection successfully established. May appear multiple times on reconnect — normal unless more than a few times per hour. |
| `connect_to <host> port <N>: failed` | Agent cannot reach the datasource — results in SOCKS host unreachable (04) |
| `ssh client exited. restarting exitCode=<N>` | SSH connection dropped. Look earlier in logs for the cause. |
| `client_loop: ssh_packet_write_poll: ... Broken pipe` | Connection closed by network conditions (packet loss etc.) — not actionable, typically beyond anyone's control |
| `Connection to private-datasource-connect-<region>.grafana.net closed by remote host.` | PDC server closed the connection, agents auto-reconnects. This is expected and normal behavior, however if it is causing persistent issues, please contact Grafana Support |
| `kex_exchange_identification: read: Connection reset by peer` | Something in the PDC system rejected the SSH connection |
| `limit of connections for stack and network reached` | Exit code 254 — 50-agent limit reached |
| `debug1: channel <N>: connected to <address> port <port>` | _(debug logging only)_ TCP connection to datasource established successfully |

## Key Health Metrics

| Metric | Healthy Value | Meaning |
|--------|--------------|---------|
| `numAuthenticatedAgents` | > 0 | Agent cert accepted by gateway |
| `numConnectedAgents` | > 0 | SSH tunnel established |
| `dataPathHealthy` | true | Proxy can open channel to a datasource |

## SSH Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 253 | Load-balancing: PDC server already has an active connection for this network, agent reconnects and gets routed to a different server. Agents eventually settle. | Normal behaviour — no action needed unless it never settles |
| 254 | 50-agent limit per PDC network reached | Remove unused agents or contact Grafana Support to increase limit |
| 255 | Generic SSH exit (all remote port forwarding exits with 255 on close) | Check earlier log lines for root cause |

## SOCKS Response Codes

These appear in Grafana query errors in the format:
`socks connect tcp private-datasource-connect.hosted-grafana.svc.cluster.local:443<ADDR>:<PORT>: unknown error <ERROR>`

| Code | Name | PDC Meaning |
|------|------|-------------|
| 03 | Network unreachable | PDC can't connect to any of the customer's agents — check agent count |
| 04 | Host unreachable | Agent can't reach the datasource within 10s — network issue on customer side |
| 06 | TTL expired | Connection to datasource timed out — network issue on customer side |

## Agent Capacity

- OpenSSH is **single-threaded** — cannot use more than 1 CPU core
- Capacity limit: approximately **100–300 requests per second** per agent
- Fix: deploy additional agents with the same configuration (can reuse the same token/network)
- Production recommendation: **minimum 3 agents** for high availability

## Certificate Lifecycle

1. Agent starts → requests cert from PDC API (port 443)
2. Cert signed with short TTL (~15 min default)
3. Agent uses cert to authenticate SSH session (port 22)
4. Agent renews cert before expiry while connected

> Clock skew > 5 minutes causes cert rejection. Check with `timedatectl status`.

## Collecting Logs

| Environment | Command |
|-------------|---------|
| systemd | `journalctl -u pdc-agent -n 200 --no-pager` |
| Docker | `docker logs <container-name> --tail 200` |
| Kubernetes | `kubectl logs -l app=pdc-agent --tail=200` |
| Manual | stdout/stderr from the binary |

Add `-log.level=debug` to see SSH handshake details up to OpenSSH debug3 level (verbose).

## Monitoring

**Agent-level metrics** (Prometheus): `http://<agent-host>:8090/metrics`

**Stack-level metrics** (in `grafanacloud-usage` datasource in your Grafana Cloud stack):
- `grafanacloud_grafana_pdc_connected_agents` — connected agent count per stack and PDC network (`tunnelID` label)
- `grafanacloud_grafana_pdc_datasource_request_duration_seconds_rate5m_p90` — p90 request latency per datasource with `status_code` label

## Useful Links

- Grafana Cloud status: https://status.grafana.com
- PDC Configuration Details: Grafana Cloud > Connections > Private data source connect
- PDC Documentation: https://grafana.com/docs/grafana-cloud/connect-externally-hosted/private-data-source-connect/
- PDC Troubleshooting docs: https://grafana.com/docs/grafana-cloud/connect-externally-hosted/private-data-source-connect/troubleshooting/
- PDC Configuration docs: https://grafana.com/docs/grafana-cloud/connect-externally-hosted/private-data-source-connect/configure-pdc/
- SOCKS spec: https://en.wikipedia.org/wiki/SOCKS
