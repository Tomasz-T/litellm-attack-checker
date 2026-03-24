---
name: litellm-attack-checker
description: Check if workstation is affected by the litellm 1.82.7/1.82.8 supply chain attack (2026-03-24). Scans for compromised packages, malicious files, persistence backdoors, C2 indicators, and K8s lateral movement.
---

# litellm Supply Chain Attack Checker

On 2026-03-24, litellm versions 1.82.7 and 1.82.8 on PyPI were compromised by threat actor **TeamPCP** (same group behind Trivy, KICS, CanisterWorm compromises). The malware harvests credentials (SSH, AWS, GCP, Azure, K8s, .env, shell history, crypto wallets), exfiltrates them to `models.litellm.cloud`, installs a persistent C2 backdoor, and spreads to Kubernetes clusters.

**Two different vectors:**
- **1.82.7**: malicious code injected into `litellm/proxy/proxy_server.py`
- **1.82.8**: malicious `litellm_init.pth` file that executes on every Python process startup

The attack was discovered when litellm was pulled in as a **transitive dependency by an MCP plugin** running inside Cursor.

Sources:
- Callum McMahon / FutureSearch, 2026-03-24: https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
- The Hacker News: https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html
- ARMO analysis: https://www.armosec.io/blog/litellm-supply-chain-attack-backdoor-analysis/

## When to use

Use this skill when the user asks to:
- Check if they're affected by the litellm attack
- Scan for litellm malware / TeamPCP compromise
- Check workstation security after the litellm compromise
- Verify their Python environments are clean

## Instructions

Run ALL checks below via Bash (adapt commands to the current OS). Report each result clearly as CLEAN or FOUND. At the end, provide a summary and remediation steps for any findings.

If version is compromised, treat the system as compromised and follow remediation. Do not just upgrade -- the payload may have already run.

### Check 1: Compromised litellm versions installed

Search for ALL litellm installations across the system — not just the active pip environment. Use `find` to locate every `METADATA` file inside `litellm*.dist-info` directories under `$HOME` (this covers virtualenvs, uv cache, pip cache, and any project `.venv`/`venv` directories). Extract the `Version:` line from each METADATA file and report all found versions with their paths.

Flag as **CRITICAL** if any version is `1.82.7` or `1.82.8`. Version `1.82.6` is the last known clean release.

Example command:
```bash
find "$HOME" -name "METADATA" -path "*litellm*dist-info*" 2>/dev/null | while read f; do
  ver=$(grep -m1 "^Version:" "$f" | awk '{print $2}')
  echo "$f -> $ver"
  case "$ver" in 1.82.7|1.82.8) echo "*** CRITICAL: COMPROMISED VERSION ***";; esac
done
```

### Check 2: Malicious files and hashes

**2a.** Search for `litellm_init.pth` in all Python site-packages directories, uv cache, pip cache, and virtualenvs in common project directories under home. Also scan any `.pth` files in site-packages for suspicious patterns (base64, subprocess, exec).

Known malicious hash for `litellm_init.pth` (SHA-256):
```
71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238
```

**2b.** Search for `litellm/proxy/proxy_server.py` and verify its hash. Known malicious hash (SHA-256, from 1.82.7):
```
a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b
```

Any match is **CRITICAL** - the malware payload is present on disk.

### Check 3: Persistence backdoor and C2 artifacts

Check if these files exist:

**Definitive indicators** (CRITICAL on their own):
- `~/.config/sysmon/sysmon.py` (local user backdoor - polls `checkmarx.zone/raw` every 50 minutes)
- `~/.config/systemd/user/sysmon.service` (systemd persistence described as "System Telemetry Service", Linux only)
- `/root/.config/sysmon/sysmon.py` (root backdoor, if accessible)
- `/tmp/tpcp.tar.gz` (exfiltration archive - name is specific to this malware)

**Suspicious in combination** (flag only if other checks also hit - these names could belong to legitimate software):
- `/tmp/pglog` (C2 payload download location)
- `/tmp/.pg_state` (C2 state tracker)
- `/tmp/session.key`, `/tmp/payload.enc`, `/tmp/session.key.enc` (encryption artifacts)

On Linux also check if the sysmon systemd user service is active.

On Windows also check for a `sysmon` scheduled task.

Any definitive indicator is **CRITICAL** - the malware has already executed. Suspicious files are **WARNING** if found alone, **CRITICAL** if found alongside other indicators.

### Check 4: Network indicators

Search shell history files (bash, zsh, fish, PowerShell) and system logs (syslog if available) for these domains:
- `models.litellm.cloud` (exfiltration endpoint)
- `checkmarx.zone` (C2 polling endpoint)

Also check the system hosts file for any `litellm.cloud` or `checkmarx.zone` entries.

### Check 5: Kubernetes indicators

Only if `kubectl` is available. Check all namespaces for pods matching `node-setup-*`. The malware creates pods with these characteristics:
- **Name pattern:** `node-setup-{node_name}` (node name truncated to 35 chars) in `kube-system` namespace
- **Container name:** `setup`
- **Image:** `alpine:latest`
- **Security:** `privileged: true`, `hostPID: true`, `hostNetwork: true`
- **Mount:** entire host filesystem (`/`) mounted at `/host`
- **Tolerations:** `operator: Exists` (runs on ALL nodes including control-plane)
- **restartPolicy:** `Never`

Flag matching pods for investigation. Also check if cluster secrets were accessed across namespaces - the malware reads all secrets before attempting pod creation.

## Summary format

After all checks, present results like this:

```
=== litellm Attack Scan Results ===

Check 1 (Compromised package):   CLEAN / CRITICAL
Check 2 (Malicious files/hashes): CLEAN / CRITICAL
Check 3 (Persistence/C2):         CLEAN / CRITICAL
Check 4 (Network indicators):     CLEAN / WARNING
Check 5 (K8s lateral movement):   CLEAN / CRITICAL / SKIPPED

Overall: CLEAN / AFFECTED
```

## Remediation (only show if any findings - do not perform remediation automatically)

If ANY check returns a finding:

1. **Remove compromised litellm immediately**: uninstall from all environments, delete any `litellm_init.pth` files found, purge pip and uv caches to prevent reinstallation from cached wheels.

2. **Remove persistence**: delete `~/.config/sysmon/` directory, the systemd service file, and all temp artifacts (`/tmp/pglog`, `/tmp/.pg_state`, `/tmp/tpcp.tar.gz`, `/tmp/session.key`, `/tmp/payload.enc`, `/tmp/session.key.enc`). On Linux, disable the sysmon systemd user service.

3. **Rotate ALL credentials** (assume compromised): SSH keys, AWS/GCP/Azure credentials, `.env` secrets, database passwords, API tokens.

4. **Kubernetes** (if applicable): delete `node-setup-*` pods in kube-system, audit all cluster secrets for unauthorized access, check for unknown ServiceAccounts, inspect nodes for `/root/.config/sysmon/sysmon.py`.

5. **Pin litellm** to a known-good version (1.82.6 or earlier) or remove it entirely until the maintainers confirm the package is safe.

## References

- Threat actor: **TeamPCP** (also behind Trivy, KICS, CanisterWorm compromises)
- Compromised versions: 1.82.7, 1.82.8 (yanked from PyPI as of 20:15 UTC)
- Last clean version: 1.82.6
- Malicious hashes (SHA-256):
  - `litellm_init.pth`: `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238`
  - `proxy_server.py` (1.82.7): `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b`
- Exfiltration endpoint: `models.litellm.cloud`
- C2 endpoint: `checkmarx.zone/raw` (polled every 50 min)
- Persistence: `~/.config/sysmon/sysmon.py` + systemd service "System Telemetry Service"
- C2/exfil artifacts: `/tmp/pglog`, `/tmp/.pg_state`, `/tmp/tpcp.tar.gz`, `/tmp/session.key`, `/tmp/payload.enc`, `/tmp/session.key.enc`
- K8s: privileged `node-setup-*` pods in `kube-system`, `alpine:latest`, host root mounted at `/host`
- GitHub issue: https://github.com/BerriAI/litellm/issues/24512
- FutureSearch: https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
- The Hacker News: https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html
- ARMO: https://www.armosec.io/blog/litellm-supply-chain-attack-backdoor-analysis/
- Snyk: https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/
- Endor Labs: https://www.endorlabs.com/learn/teampcp-isnt-done
