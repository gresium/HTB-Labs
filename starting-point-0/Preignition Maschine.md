# Preignition - Hack The Box Writeup

![Difficulty](https://img.shields.io/badge/Difficulty-Very%20Easy-brightgreen) ![OS](https://img.shields.io/badge/OS-Linux-blue) ![Category](https://img.shields.io/badge/Category-Network%20Enumeration-orange)

---

## Machine Information

| Attribute | Details |
|-----------|---------|
| **Machine Name** | Preignition |
| **Difficulty** | Very Easy |
| **Platform** | Hack The Box |
| **Operating System** | Linux |
| **Category** | Basic Enumeration / Authentication Failure |
| **Focus** | Service Identification & Access Control |

---

## Table of Contents

- [Overview](#overview)
- [Initial Enumeration](#initial-enumeration)
- [Service Identification](#service-identification)
- [Web Enumeration](#web-enumeration)
- [Exploitation](#exploitation)
- [Post Exploitation](#post-exploitation)
- [Key Takeaways](#key-takeaways)

---

## Overview

Preignition is a **"Very Easy"** difficulty machine from Hack The Box that focuses on fundamental web enumeration and authentication failures. This box demonstrates the importance of proper access controls and the risks associated with default credentials on administrative interfaces.

Rather than exploiting a complex vulnerability, this machine emphasizes the critical nature of basic security hygiene and the dangers of exposed administrative panels with weak authentication mechanisms.

**Learning Objectives:**
- Web service enumeration techniques
- Directory/endpoint discovery
- Understanding authentication weaknesses
- Recognizing the impact of default credentials

---

## Initial Enumeration

### Port Scanning

First, we conduct a comprehensive port scan to identify running services:

```bash
nmap -sC -sV -oN nmap/initial 10.10.10.X
```

**Results:**
```
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
```

**Key Findings:**
- Single HTTP service running on port 80
- Web server: nginx 1.14.2
- No additional services exposed

> 💡 The limited attack surface suggests we'll focus primarily on web-based enumeration and exploitation.

---

## Service Identification

### HTTP Service Analysis

Visiting the web service on port 80 reveals a default or basic web page. Initial observations:

- Standard web application interface
- No immediately obvious vulnerabilities on the homepage
- Application appears to be a lightweight web service
- No version information or framework details exposed

At this stage, deeper enumeration is required to identify potential attack vectors.

---

## Web Enumeration

### Directory Brute-forcing

Web services often contain hidden or unlinked administrative interfaces. We use directory enumeration tools to discover these endpoints:

```bash
gobuster dir -u http://10.10.10.X -w /usr/share/wordlists/dirb/common.txt
```

**Alternative tools:**
```bash
# Using ffuf
ffuf -u http://10.10.10.X/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Using dirb
dirb http://10.10.10.X /usr/share/wordlists/dirb/common.txt
```

### Discovery Results

```
===============================================================
Gobuster v3.1.0
===============================================================
[+] Url:                     http://10.10.10.X
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Status codes:            200,204,301,302,307,401,403
===============================================================

/admin.php            (Status: 200) [Size: 999]

===============================================================
```

### Critical Finding
**🎯 Administrative login panel discovered at `/admin.php`**

**Key Observations:**
- ✅ Endpoint returns HTTP 200 (accessible)
- ❌ Not linked from the main application
- ❌ No IP-based access restrictions
- ⚠️ Authentication form present

> ⚠️ **Security Issue:** This represents security through obscurity rather than proper access controls.

---

## Exploitation

### Authentication Testing

With an administrative login panel discovered, we test for common authentication weaknesses:

#### Testing Default Credentials

Administrative interfaces often suffer from:
- ❌ Default credentials left unchanged
- ❌ Weak password policies
- ❌ No account lockout mechanisms
- ❌ No multi-factor authentication

**Common default credential combinations to test:**
```
admin:admin
admin:password
administrator:administrator
admin:[blank]
root:root
admin:admin123
```

### Successful Authentication

Testing common default credentials:

```
Username: admin
Password: admin
```

**Result:** ✅ **Successful authentication with full administrative access**

**Evidence:**
- ✅ Successfully logged into administrative panel
- ✅ Full access to application controls
- ❌ No MFA or additional verification required
- ❌ No rate limiting on authentication attempts observed

---

## Post Exploitation

### Administrative Access

Upon successful authentication, we gain access to the administrative interface with the following capabilities:

**Available Functionality:**
- 🔧 Full application configuration access
- 👥 User management capabilities
- ⚙️ System settings modification
- 💾 Potential database access
- 📊 Application monitoring and logs

### Flag Retrieval

The flag is accessible through the administrative interface:

```
HTB{[FLAG_REDACTED]}
```

### Impact Assessment

This vulnerability represents a **CRITICAL** security failure with the following impacts:

#### Technical Impact
- ✅ Complete application compromise
- ✅ Unrestricted administrative access
- ✅ Potential for data exfiltration
- ✅ Ability to modify application behavior
- ✅ Possible pivot point for further network access

#### Real-World Impact
In a production environment, this would allow an attacker to:
- 🔓 Access sensitive data and user information
- 🗑️ Modify or delete critical application data
- 🚪 Create backdoor accounts for persistence
- 💾 Potentially access backend systems or databases
- 🔄 Use the compromised system for lateral movement

---

## Key Takeaways

### 🎯 Technical Lessons

#### 1️⃣ Web Enumeration is Essential
- Directory brute-forcing remains a highly effective technique
- Hidden endpoints do not equal secured endpoints
- Automated tools should be complemented with manual testing
- Administrative interfaces are high-value targets

#### 2️⃣ Default Credentials are a Critical Vulnerability
- Common across all types of systems and applications
- Often overlooked during deployment
- Should be the first thing tested on any login interface
- Easily prevented with proper deployment procedures

#### 3️⃣ Obscurity ≠ Security
- Hiding administrative interfaces does not protect them
- Security must be enforced through proper access controls
- URL paths can be easily enumerated
- Defense-in-depth is essential

#### 4️⃣ Authentication is the First Line of Defense
- Strong authentication is critical for administrative access
- Multi-factor authentication should be mandatory
- Account lockout policies prevent brute-force attacks
- Monitoring and logging are essential for detection

---

## 🛡️ Defensive Recommendations

### Immediate Actions
| Priority | Action | Timeline |
|----------|--------|----------|
| 🔴 CRITICAL | Remove or change all default credentials | Immediately |
| 🔴 CRITICAL | Implement strong password policies | Within 24h |
| 🟠 HIGH | Enable multi-factor authentication | Within 48h |
| 🟠 HIGH | Restrict admin panel access by IP/network | Within 48h |

### Access Control Best Practices
- ✅ Implement role-based access control (RBAC)
- ✅ Follow principle of least privilege
- ✅ Use network segmentation for administrative interfaces
- ✅ Regular access reviews and audits

### Monitoring and Detection
- ✅ Log all authentication attempts (successful and failed)
- ✅ Alert on multiple failed login attempts
- ✅ Monitor for unusual access patterns
- ✅ Implement automated security scanning

### Long-term Security
- ✅ Security-focused deployment checklists
- ✅ Regular penetration testing
- ✅ Security awareness training for development teams
- ✅ Automated configuration validation

---

## 🔧 Tools Used

| Tool | Purpose |
|------|---------|
| **Nmap** | Network scanning and service enumeration |
| **Gobuster** | Directory and file brute-forcing |
| **Burp Suite** | Web application security testing |
| **Browser DevTools** | HTTP request/response analysis |

---

## 📚 References

- [OWASP Top 10 - A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

**Author:** Security Researcher  
**Date:** February 7, 2026  
**Machine IP:** 10.10.10.X  
**Difficulty:** Very Easy  
**Points:** 20

---

*This writeup is for educational purposes only. Always ensure you have proper authorization before testing any systems.*
