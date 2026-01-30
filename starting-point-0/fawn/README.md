# HTB Fawn — FTP Enumeration & Cleartext Protocol Risks

## Context
This lab focuses on understanding the risks of legacy file transfer protocols and the importance of encryption and access controls when exposing services over a network.

Rather than exploiting a vulnerability, the lab demonstrates how **protocol design decisions** can directly impact security.

---

## Service Enumeration
Initial enumeration identified an FTP service exposed on the standard port.

FTP is a legacy protocol that:
- Transmits credentials and data in cleartext
- Lacks built-in encryption
- Relies heavily on correct configuration to be secure

Its presence immediately raises security concerns in modern environments.

---

## Protocol Analysis
Further interaction with the FTP service revealed:
- The specific FTP server implementation and version
- The underlying operating system type
- Standard FTP response codes confirming authentication state

Understanding protocol responses is critical, as they often leak operational details useful to attackers.

---

## Authentication & Access
Successful authentication allowed interaction with the remote file system.

Once authenticated, common file and directory listing commands exposed available resources, demonstrating how quickly data can become accessible when access controls are weak or overly permissive.

---

## Data Exposure
The ability to retrieve files from the server highlights a key risk:
> Any data exposed via cleartext protocols can be intercepted, manipulated, or misused.

Even when credentials are valid, the lack of encryption makes such services unsuitable for untrusted networks.

---

## Key Lessons Learned
- Legacy protocols introduce systemic security risks
- Cleartext authentication is unacceptable in modern environments
- Service version and OS fingerprinting provide valuable attacker context
- Protocol-level knowledge is as important as exploitation skills

---

## Defensive Takeaways
- Replace FTP with encrypted alternatives such as SFTP
- Restrict file transfer services by network segmentation
- Monitor exposed services and protocol usage
- Avoid exposing legacy protocols to external networks
