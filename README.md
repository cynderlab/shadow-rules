# Shadow Rules Generator for Suricata

[![Generate and Release Rules](https://github.com/cynderlab/shadow-rules/actions/workflows/release.yml/badge.svg)](https://github.com/cynderlab/shadow-rules/actions/workflows/release.yml)

**High-Fidelity Visibility for Shadow IT, Shadow OT, and Network Hygiene Audits.**

This project is a specialized engine designed to generate Suricata IDS rules that provide immediate visibility into hidden network risks. By transforming community domain lists, curated technical endpoints, and manual protocol signatures into professional-grade network signatures, it enables security teams to **audit and monitor** what is *actually* running on their network.

The primary goal is **network auditing**: identifying insecure configurations, unencrypted protocols, unauthorized services, and industrial assets that may not be visible through traditional monitoring. All rules are tuned for audit scenarios with controlled thresholds to produce actionable reports without alert fatigue.

---

## What can you obtain from this project?

The primary output is a set of optimized Suricata `.rules` files categorized by risk type. These rules allow you to:

*   **Audit Shadow AI**: Identify unauthorized use of GenAI tools (ChatGPT, Claude, Perplexity) that could lead to data leakage.
*   **Discover Shadow OT**: Map industrial assets (PLCs, HMIs) communicating via Modbus, S7comm, BACnet, KNXnet/IP, DNP3, and more.
*   **Verify Endpoint Security**: Confirm the presence and health of EDR/AV agents (CrowdStrike, SentinelOne, Defender) by monitoring their telemetry channels.
*   **Detect Insecure Protocols**: Flag unencrypted legacy protocols with deep packet inspection:
    - **Database credentials in cleartext**: MySQL, PostgreSQL, MSSQL, Redis, MongoDB
    - **Authentication protocols**: FTP, POP3, IMAP (LOGIN + SASL PLAIN), SMTP, LDAP Simple Bind
    - **Remote access without encryption**: Telnet, VNC (RFB), RDP without NLA/TLS, rlogin, rsh
    - **HTTP credential exposure**: POST body credentials, GET parameters, Basic/Bearer/NTLM/Kerberos auth headers
    - **Network services**: SNMP v1/v2c (no SNMPv3), NFS with AUTH_SYS (no Kerberos), Syslog cleartext, TFTP
    - **VoIP**: SIP cleartext (INVITE/REGISTER)
    - **Legacy SMB**: SMBv1 negotiation detection
*   **Map Industrial Networks**: Detect OT/ICS protocols including Siemens S7comm, Modbus TCP, OPC-UA, IEC 60870-5-104, EtherNet/IP (CIP), BACnet/IP, KNXnet/IP, DNP3, Omron FINS, HART-IP, MQTT, CoAP, and more.
*   **Maintain Compliance**: Ensure all network entities adhere to established security policies.

---

## Audit-Oriented Design

### Threshold Strategy

All rules that can generate repetitive traffic use **controlled thresholds** to balance visibility with noise reduction:

```
threshold: type limit, track by_both, count 1, seconds 3600;
```

*   **`track by_both`**: Limits alerts per **source-destination pair**, not just source IP. This ensures you see every unique communication flow (e.g., Host A -> Server X and Host A -> Server Y both generate alerts), which is critical for audit reports that need to map all insecure communication paths.
*   **`seconds 3600`** (1 hour): One alert per pair per hour is sufficient to confirm the existence of insecure traffic without flooding logs.

### Protocol Detection Strategy

Rules use the most reliable detection method for each protocol:

| Strategy | When | Example |
|---|---|---|
| **App-layer keywords** | Parser compiled and active in Suricata | `smb.version:1`, `sip.method`, `http.method` |
| **Raw byte matching** | Parser not available or unreliable for handshakes | SNMP (ASN.1 bytes), LDAP (BER encoding), RDP (X.224), NFS (RPC) |
| **Port + content** | Protocol uses fixed ports with identifiable patterns | MySQL, MSSQL (TDS), Redis (RESP), POP3, IMAP |

Before deploying, verify which app-layer parsers are compiled in your Suricata build:

```bash
suricata --build-info | grep -iE 'smb|telnet|pgsql|rfb|ftp|smtp|sip|http'
suricata --list-keywords | grep -iE 'smb\.|snmp\.|sip\.|ldap\.'
```

---

## How It Works

The generator follows a strict pipeline to ensure rule quality and consistency:

1.  **Manifest Loading**: Reads `config/manifest.yaml` to determine which categories to process and in what order.
2.  **Multi-Provider Fetching**: Downloads domain lists from external providers (e.g., `v2fly`) or processes local definitions.
3.  **Entity Resolution**: Merges automatic feeds with `manual_domains` and `custom_signatures`.
4.  **Global Deduplication**: Each domain/signature is processed only once (the first category in the manifest "wins"), preventing alert fatigue.
5.  **Professional Formatting**: Wraps every detection in a standard template including:
    *   **Dynamic Priority**: Mapped from 1 (Critical) to 4 (Informational).
    *   **Rich Metadata**: Includes `created_at`, `vendor`, `category`, and `service`.
    *   **Persistent SIDs**: Every signature keeps its unique ID forever via `state.json`.
6.  **Output Generation**: Produces individual category files and a consolidated `all_shadow_rules.rules`.

---

## Project Structure

```
config/
  manifest.yaml              # Main entry point — defines processing order
  feeds/                     # Domain-based categories (automatic or manual)
    genai.yaml               # AI tools tracking
    endpoint_security.yaml   # EDR/AV telemetry endpoints
    ...
  custom/                    # Logic-based signatures (deep packet inspection)
    insecure_protocols.yaml  # Legacy/Unencrypted protocol detection (40+ rules)
    industrial_protocols.yaml # OT/ICS protocol discovery (35+ rules)
src/
  models.py                  # Strict data validation (DTOs)
  orchestrator.py            # High-level processing logic
  generator.py               # Suricata rule engine
  providers.py               # Extensible feed architecture
  sid_manager.py             # SID persistence and state management
```

---

## Configuration Example

Each YAML file in `config/` defines a category. You can specify a default `severity` and `priority` at the category level, and optionally override them for individual custom signatures.

```yaml
name: "Remote Control"
severity: 3
priority: 3
feeds:
  v2fly: [ "teamviewer" ]    # Automatic updates from community lists
manual_domains:
  - name: "AnyDesk"          # Precise manual additions
    domains: [ "anydesk.com" ]
custom_signatures:
  - name: "Telnet Usage"     # Logic-based rules (non-domain)
    proto: "tcp"
    dst: "any 23"
    options: "flow:established,to_server;"
    severity: 2              # Optional override
    priority: 2              # Optional override
```

If `severity` or `priority` are not specified, they default to **3**.

### Severity and Priority Levels

The following table defines how each level is interpreted within the generator:

| Value | Label | Interpretation |
| :---: | :--- | :--- |
| **1** | **Critical** | High-impact risks, cleartext credentials for critical systems, or high-risk malicious content. |
| **2** | **Major** | Significant security policy violations, industrial protocol actions, or sensitive service exposure. |
| **3** | **Minor** | **(Default)** Common insecure protocols, general Shadow IT discovery, and standard auditing. |
| **4** | **Informational** | Telemetry endpoints, service heartbeat, and low-risk visibility for network hygiene. |

### Custom Signatures

Custom signatures support full Suricata rule syntax with YAML structure:

```yaml
custom_signatures:
  - name: "SNMP v1 Successful Access Detected"
    proto: "udp"
    src: "$HOME_NET 161"
    dst: "any any"
    options: 'content:"|30|"; depth:1; content:"|02 01 00|"; distance:0; within:10; content:"|a2|"; distance:0; within:40; threshold: type limit, track by_both, count 1, seconds 3600;'
```

### Domain Matching
*   **Standard**: `anydesk.com` matches the domain and all subdomains (uses `endswith`).
*   **Exact (`full:`)**: `full:api.sentinelone.net` matches **only** that specific hostname (uses `bsize` and `isdataat`). Use this for telemetry endpoints to avoid false positives from web browsing.

---

## Local Setup

1.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
2.  **Run the generator**:
    ```bash
    python3 main.py
    ```
3.  **Verify results**: Check the `rules/` directory for the generated `.rules` files.

## Rule Validation

Before deploying the rules to production, it is highly recommended to validate their syntax using the Suricata binary:

```bash
# Validate the consolidated rules file
suricata -T -S rules/all_shadow_rules.rules
```

If you have a specific `suricata.yaml` configuration file, you can perform a full configuration test:

```bash
suricata -T -c /etc/suricata/suricata.yaml -S rules/all_shadow_rules.rules
```

A successful validation will end with a message similar to:
`Suricata configuration validation successful.`
