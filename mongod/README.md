# HTB Mongod — Unauthenticated MongoDB Exposure

## Context
This lab demonstrates the risks of exposing a database service directly to the network without enforcing authentication or access restrictions.

MongoDB is commonly deployed for internal use. When exposed externally with default settings, it can allow full database access without credentials, leading to immediate data compromise.

---

## Service Enumeration
Initial network enumeration revealed **two open TCP ports**, one of which was associated with MongoDB.

Service identification confirmed:
- **MongoDB 3.6.8** running on the default port **27017**

MongoDB is a **NoSQL** database and does not use tables or schemas in the traditional SQL sense.

---

## Database Access
Connecting to the MongoDB service did **not require authentication**.

An interactive MongoDB shell was launched, allowing direct interaction with the database server.

From the shell, it was possible to:
- Enumerate all available databases
- List collections within a database
- Query and dump stored documents

This level of access should never be possible from an untrusted network.

---

## Data Enumeration
After identifying the relevant database, collections were listed and inspected.

A collection containing sensitive data was discovered and queried, revealing the stored flag.

This highlights how unauthenticated database access can result in full data disclosure without exploiting a traditional vulnerability.

---

## Security Takeaway
- Databases should **never** be exposed directly to the internet
- Authentication must be enforced by default
- Network-level access controls are critical for backend services

Unauthenticated database exposure is a **high-impact misconfiguration** that can lead to immediate compromise.
