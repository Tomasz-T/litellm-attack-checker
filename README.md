# litellm-attack-checker

A Claude Code skill that checks your workstation for compromise from the **litellm 1.82.7/1.82.8 supply chain attack** (2026-03-24). Works on macOS, Linux, and Windows.

## What happened

On March 24, 2026, threat actor **TeamPCP** compromised litellm versions 1.82.7 and 1.82.8 on PyPI. The package contains a malicious `.pth` file (`litellm_init.pth`, 34,628 bytes) that executes automatically on every Python process startup. No corresponding release exists on GitHub -- the package was uploaded directly to PyPI from a compromised maintainer account.

The attack was discovered when litellm was pulled in as a **transitive dependency by an MCP plugin** running inside Cursor, causing a fork bomb that crashed the machine (a bug in the malware).

TeamPCP is the same group behind the Trivy, KICS, and CanisterWorm compromises.

**Two different vectors:**
- **1.82.7**: malicious code in `litellm/proxy/proxy_server.py`
- **1.82.8**: malicious `litellm_init.pth` that runs on every Python startup

**The malware:**
- Harvests SSH keys, .env files, AWS/GCP/Azure/K8s credentials, database passwords, shell history, and crypto wallets
- Encrypts and exfiltrates data to `models.litellm.cloud`
- Installs persistent C2 backdoor at `~/.config/sysmon/sysmon.py` (polls `checkmarx.zone/raw` every 50 min)
- If Kubernetes access is available: reads all cluster secrets and creates privileged `node-setup-*` pods on every node

## What this skill checks

| Check | What | Severity |
|-------|------|----------|
| 1 | litellm 1.82.7 or 1.82.8 installed via pip | CRITICAL |
| 2 | Malicious files by name and SHA-256 hash (`litellm_init.pth`, `proxy_server.py`) | CRITICAL |
| 3 | Persistence backdoor (`~/.config/sysmon/`), C2 artifacts, exfil archive (`/tmp/tpcp.tar.gz`) | CRITICAL |
| 4 | Exfil/C2 domains in shell history and syslog (`models.litellm.cloud`, `checkmarx.zone`) | WARNING |
| 5 | Privileged `node-setup-*` pods in Kubernetes kube-system | CRITICAL |

## Installation

```bash
git clone https://github.com/Tomasz-T/litellm-attack-checker.git
cd litellm-attack-checker
cp -r litellm-attack-checker ~/.claude/skills/
```

## Usage

In Claude Code, either:

- Type `/litellm-attack-checker`
- Or ask: *"Check if I'm affected by the litellm supply chain attack"*

Claude will run each check and report results.

## Remediation

If affected:

1. **Remove litellm** from all environments + purge pip/uv caches
2. **Delete persistence** files at `~/.config/sysmon/`, `/tmp/pglog`, `/tmp/.pg_state`, `/tmp/tpcp.tar.gz`, `/tmp/session.key`, `/tmp/payload.enc`, `/tmp/session.key.enc`
3. **Rotate ALL credentials** -- SSH, AWS, GCP, Azure, .env secrets, API tokens, DB passwords
4. **Audit Kubernetes** if applicable -- delete `node-setup-*` pods, review secrets access, check nodes for backdoor
5. **Pin or remove litellm** -- last clean version is 1.82.6

## References

- [FutureSearch: Supply Chain Attack in litellm 1.82.8](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/)
- [The Hacker News: TeamPCP Backdoors LiteLLM](https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html)
- [ARMO: LiteLLM Supply Chain Attack Backdoor Analysis](https://www.armosec.io/blog/litellm-supply-chain-attack-backdoor-analysis/)
- [Snyk: Poisoned Security Scanner Backdooring LiteLLM](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/)
- [Endor Labs: TeamPCP Isn't Done](https://www.endorlabs.com/learn/teampcp-isnt-done)
- [GitHub Issue #24512](https://github.com/BerriAI/litellm/issues/24512)
- Compromised versions: **1.82.7, 1.82.8** (yanked as of 20:15 UTC)
- Malicious hashes (SHA-256):
  - `litellm_init.pth`: `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238`
  - `proxy_server.py` (1.82.7): `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b`
- Exfiltration: `models.litellm.cloud`
- C2: `checkmarx.zone/raw`

## Disclaimer

This tool is provided "as is", without warranty of any kind. The author takes no responsibility for any damages or losses resulting from its use. Use at your own risk.

## License

MIT
