# HTB Meow — Basic Network Enumeration & Insecure Service Exposure

## Context
This lab introduces the most fundamental phase of a penetration test: identifying exposed network services and validating authentication controls.

Although technically simple, it demonstrates how **severely insecure defaults** can still exist and lead directly to full system compromise.

---

## Initial Enumeration
A basic network scan revealed a minimal attack surface with a single notable open port.

Rather than assuming safety due to limited exposure, the focus was on identifying **what service was running** and whether it enforced proper authentication.

This reinforces an important mindset:
> A small attack surface does not mean a secure system.

---

## Service Identification
The exposed service was a legacy remote access protocol that transmits data in cleartext and lacks modern security controls.

Services of this type are considered insecure by default and should not be exposed in production environments, especially without access restrictions.

---

## Authentication Failure
Connection to the service revealed a critical misconfiguration:
- A privileged account was accessible
- No password was required

This represents a complete breakdown of authentication and access control.

No exploitation or bypass was required — access was granted directly.

---

## Resulting Impact
Because the service ran with high privileges, successful authentication immediately resulted in full system compromise.

This illustrates how:
- Authentication failures are often more dangerous than software vulnerabilities
- Misconfigurations can be fatal even on otherwise simple systems

---

## Key Lessons Learned
- Enumeration must always include service identification
- Legacy services should be treated as high-risk
- Authentication controls are non-negotiable
- Simplicity does not equal safety

---

## Defensive Takeaways
- Disable legacy remote access services
- Enforce strong authentication on all exposed interfaces
- Restrict administrative access by network segmentation
- Audit systems for default or blank credentials
