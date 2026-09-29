# Homelab Write-ups

Short write-ups from my personal SOC homelab (Proxmox-based), built while working toward Blue Team Level 1 and a SOC analyst role. Each one covers the goal, the architecture, and one real problem I ran into and how I diagnosed it , not a full lab journal! 

## Projects

- [Splunk AD Lab Deployment](./splunk-ad-lab-deployment.md) — deploying Sysmon and the Splunk Universal Forwarder across a small Active Directory lab via GPO, and a silent log-subscription failure caused by the Forwarder's virtual service account.
- [Atomic Red Team: T1053.005 Scheduled Task](./red-atomic-team.md) — running an Atomic Red Team test against my own lab, and building a Splunk detection for the created scheduled task that does not fire on legitimate Windows tasks.
- [Atomic Red Team: T1003.001 LSASS Credential Dumping](./t1003-001-lsass-credential-dumping.md) — dumping LSASS memory with Task Manager, parsing it offline with Mimikatz, fighting through two separate Windows Defender layers, and finding the exact point where a Sysmon detection can and can't see the technique.
