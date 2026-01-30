
# HTB Redeemer — Unauthenticated Redis Exposure

## Context
This lab demonstrates how exposing a database service without authentication can lead to immediate compromise.

Redis is frequently deployed as an internal component, and when exposed externally without access controls it becomes a high-impact attack surface.

---

## Service Enumeration
Network enumeration revealed a single open port commonly associated with Redis.

Unlike many services, Redis often runs without authentication by default, under the assumption that it is only accessible from trusted networks.

This assumption is dangerous.

---

## Redis Access
Connecting to the Redis service required no credentials.

Once connected, it was possible to:
- Retrieve server configuration and runtime information
- Identify database structure and key usage
- Interact directly with stored data

This level of access should never be possible from an untrusted network.

---

## Data Exposure
Inspection of the in-memory database revealed multiple keys containing sensitive values.

Even without modifying data or escalating privileges, the ability to read internal application data represents a critical breach.

---

## Impact
Unauthenticated Redis access enables:
- Full data disclosure
- Data manipulation
- Potential remote code execution depending on configuration

In real environments, this often leads to complete system compromise.

---

## Key Lessons Learned
- Databases must never be exposed without authentication
- “Internal-only” assumptions routinely fail
- In-memory databases are not inherently safer
- Service hardening is as important as patching

---

## Defensive Takeaways
- Bind Redis to localhost or internal interfaces only
- Enforce authentication and ACLs
- Restrict access via firewall rules
- Monitor for unexpected external connections
