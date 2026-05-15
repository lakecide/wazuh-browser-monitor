# Wazuh Browser History Monitor

## Objective

This guide shows how to deploy a Python-based browser history monitoring script from a Wazuh manager to Windows endpoints using the Wazuh command wodle. The script collects browsing activity from Chrome, Edge, and Brave, and forwards it to the Wazuh manager as structured JSON alerts.

## Requirements

- Wazuh dashboard administrator access
- SSH or console access to the Wazuh manager
- Windows endpoints running the Wazuh agent
- Python 3.x installed **system-wide** on each Windows endpoint (see [Prerequisites](#prerequisites))
- `wazuh_command.remote_commands=1` enabled on each agent

## Overview

The workflow includes:

1. Meeting prerequisites on each Windows endpoint
2. Creating an agent group on the manager
3. Adding the monitoring script to the shared manager path
4. Deploying and scheduling the script with the `command` wodle
5. Configuring `logcollector` to ingest the JSON output
6. Adding the decoder and rules on the manager
7. Verifying alerts in the Wazuh dashboard

---

## Prerequisites

### Python must be installed system-wide

The Wazuh agent service runs as `SYSTEM` on Windows. Python installed via the **Microsoft Store** uses app execution aliases that are only available in user context — SYSTEM cannot access them, and the wodle will fail silently.

**Required:** Install Python from [python.org](https://python.org/downloads) with the following options:

1. Run the installer as **Administrator**
2. Click **Customize installation**
3. On the Advanced Options screen, check:
   - Install Python for all users
   - Add Python to PATH

This installs Python to `C:\Program Files\Python3xx\` which SYSTEM can access.

Verify the path after install:
```cmd
where python
```
Expected output: `C:\Program Files\Python314\python.exe` (not `WindowsApps`)

### Enable remote commands on each Windows endpoint

Run PowerShell as Administrator and append the following to `local_internal_options.conf`:

```powershell
Add-Content "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" "`nsca.remote_commands=1`nwazuh_command.remote_commands=1"
```

Then restart the Wazuh agent:
```powershell
Restart-Service -Name wazuh
```

>  **Warning:** Enabling remote commands allows the Wazuh manager to execute commands on endpoints. Ensure only trusted users have access to the manager and restrict permissions appropriately.

---

## Step 1: Create an agent group on the manager

1. Open the Wazuh dashboard
2. Navigate to **Agent Management → Groups**
3. Create a group (e.g., `browser-monitor-windows`)
4. Assign the target Windows agents to this group

Refer to the [Wazuh documentation](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html) for details on creating and managing agent groups.

---

## Step 2: Add the monitoring script to the manager

On the Wazuh manager, copy the script to the shared group directory:

```bash
cp scripts/browser_monitor.py /var/ossec/etc/shared/browser-monitor-windows/
```

Replace `browser-monitor-windows` with your actual group name.

The Wazuh manager automatically syncs files in this directory to all agents in the group. The script will be available on each agent at:

```
C:\Program Files (x86)\ossec-agent\shared\browser_monitor.py
```

---

## Step 3: Configure the wodle and logcollector via `agent.conf`

In the Wazuh dashboard, open:

**Agent Management → Groups → your group → Files → agent.conf**

Add the following inside the `<agent_config>` section:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>browser-monitor</tag>
  <command>C:\Program Files\Python314\python.exe "C:\Program Files (x86)\ossec-agent\shared\browser_monitor.py"</command>
  <interval>1m</interval>
  <run_on_start>yes</run_on_start>
  <timeout>55</timeout>
  <ignore_output>no</ignore_output>
</wodle>

<localfile>
  <log_format>json</log_format>
  <location>C:\Program Files (x86)\ossec-agent\shared\browser_history.log</location>
</localfile>
```

> **Note:** Update the Python path to match the actual installation path on your endpoints. Ask users to run `where python` (in an Administrator CMD) to confirm the path before deployment.

### How the wodle works

- **`interval: 1m`** — the wodle triggers the script every 1 minute
- **`timeout: 55`** — the script is killed at 55 seconds if still running, preventing overlap with the next execution
- **`run_on_start: yes`** — runs immediately when the agent starts, without waiting for the first interval
- The script runs as a single execution (no internal loop) — it collects new history since the last run, writes JSON output, and exits cleanly

---

## Step 4: Configure the decoder on the manager

Create or edit `/var/ossec/etc/decoders/browser_decoder.xml`:

```xml
<decoder name="browser-monitor">
  <prematch>browser-monitor:</prematch>
</decoder>

<decoder name="browser-monitor-json">
  <parent>browser-monitor</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

---

## Step 5: Configure rules on the manager

Create or edit `/var/ossec/etc/rules/browser_rules.xml`:

```xml
<group name="browser,monitor example,">

  <rule id="110100" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">browser-monitor</field>
    <field name="event">browser_history</field>
    <description>Browser history: $(browser) - $(user) visited $(url)</description>
    <options>no_full_log</options>
  </rule>

  <rule id="110101" level="10">
    <if_sid>110100</if_sid>
    <field name="url">\.onion$|torproject\.org|darkweb|pastebin\.com</field>
    <description>Suspicious URL visited by $(user): $(url)</description>
    <group>suspicious_browsing,</group>
  </rule>

</group>
```

Save and restart the Wazuh manager:

```bash
systemctl restart wazuh-manager
```

---

## Step 6: Verify the deployment

### On the agent — check the wodle started

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Wait -Tail 30
```

Expected output within 1 minute of agent start:
```
wazuh-modulesd:command: INFO: Module command:browser-monitor started
wazuh-modulesd:command: INFO: Starting command 'browser-monitor'.
```

### On the agent — check the output log

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\shared\browser_history.log" -Tail 20
```

Expected JSON output:
```json
{"event": "start", "message": "Starting Browser Monitor..."}
{"event": "browser_history", "user": "john.doe", "browser": "chrome", "url": "https://example.com", "title": "Example", "visit_time": "2026-05-15T09:37:13Z", "visit_count": 1}
{"event": "done", "message": "Collection complete."}
```

### On the manager — confirm events are arriving

```bash
grep "browser-monitor" /var/ossec/logs/alerts/alerts.json | tail -20
```

---

## How the script handles common issues

| Issue | How it is handled |
|---|---|
| Browser history file locked (browser open) | Copies the SQLite DB to a temp file before reading |
| Script running as SYSTEM (no user context) | Enumerates `C:\Users` to find logged-in user profiles |
| Duplicate collection | State file tracks the last-seen timestamp per browser per user |
| Multiple browsers | Supports Chrome, Edge, and Brave out of the box |
| Script crash | Wazuh agent service restarts the wodle on the next interval |

---

## Notes

- Replace rule ID `110100–110103` with IDs that do not conflict with your existing custom rules
- Update the Python path in `agent.conf` to match the actual path on your endpoints — it varies by installation method and version
- The state file is stored at `C:\Program Files (x86)\ossec-agent\shared\browser_state.json` and persists between runs — deleting it causes a full re-collection on the next run
- Firefox uses a different database format (places.sqlite with a different schema) and is not included in this version

## Conclusion

This deployment replaces GPO-based scheduled tasks with a Wazuh-native approach. The manager handles script distribution via the shared group directory, the wodle handles scheduling, and logcollector handles log ingestion — keeping the entire pipeline inside Wazuh with no external dependencies beyond a system-wide Python installation.
