# HTB Synced — Rsync Anonymous Access

## Context
This lab demonstrates the risks of exposing an rsync service with anonymous access enabled.

Rsync is commonly used for backups and file synchronization and is often mistakenly exposed to untrusted networks.

---

## Service Enumeration
Scanning revealed a single open TCP port:
- **873** (default rsync port)

The rsync service was reachable without authentication.

---

## Rsync Interaction
Anonymous access allowed remote listing of available shares and files.

Observed characteristics:
- No credentials required
- Rsync protocol version 31
- Remote file listing permitted

---

## Key Commands Used
- `rsync`
- `--list-only`

---

## Security Takeaway
- Rsync services should never be publicly exposed
- Anonymous access must be disabled
- Backup services frequently contain sensitive data
