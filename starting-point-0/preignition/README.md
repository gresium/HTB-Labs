# HTB Preignition — Web Service Exposure & Default Credentials

## Context
This lab demonstrates how exposed web services combined with poor access controls can provide immediate administrative access.

Rather than exploiting a vulnerability, the lab focuses on **web enumeration**, discovery of hidden endpoints, and the risks of default or weak authentication.

---

## Service Enumeration
Initial network enumeration identified a web service running on the standard HTTP port.

Web services are often the most exposed attack surface and require careful inspection beyond simply loading the homepage.

---

## Web Enumeration
Directory enumeration was used to identify hidden or unlinked pages hosted by the application.

This process revealed an administrative endpoint that was not directly referenced but was accessible without additional restrictions.

Hidden pages are not protected pages.

---

## Authentication Weakness
The discovered administrative interface did not enforce proper authentication controls.

Access was granted using default or blank credentials, resulting in immediate administrative access to the application.

This represents a failure of basic security hygiene rather than a technical exploit.

---

## Impact
Gaining access to an administrative web interface allows:
- Full control over application behavior
- Potential access to backend systems or credentials
- A strong foothold for further compromise

In real environments, this often leads to escalation beyond the web application itself.

---

## Key Lessons Learned
- Web enumeration is a critical reconnaissance step
- Hidden endpoints must still be secured
- Default credentials remain a common failure point
- Authentication controls are more important than obscurity

---

## Defensive Takeaways
- Enforce strong authentication on all administrative endpoints
- Remove default credentials before deployment
- Limit access to admin interfaces by network or role
- Regularly audit web applications for exposed functionality
