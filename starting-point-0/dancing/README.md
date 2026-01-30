# HTB Dancing — SMB Enumeration & Weak Share Access

## Context
This lab demonstrates how Windows file-sharing services can become an entry point when authentication controls are weak or improperly enforced.

The focus is on **SMB enumeration**, understanding share permissions, and recognizing the risks of anonymous or low-privileged access.

---

## Service Enumeration
Network scanning identified the Server Message Block (SMB) service exposed on its standard port.

SMB is a core Windows service used for file and resource sharing, and its exposure immediately suggests:
- Share enumeration opportunities
- Authentication testing
- Potential data leakage

---

## SMB Share Discovery
Enumerating available SMB shares revealed multiple resources hosted on the system.

At this stage, the goal was not exploitation, but identifying:
- Which shares exist
- Which require authentication
- Which enforce proper access controls

This mirrors real-world internal network assessments.

---

## Authentication Weakness
One of the discovered shares was accessible without providing valid credentials.

This represents a critical access control failure, as file shares often contain sensitive business or operational data.

Even read-only access can be sufficient for reconnaissance or lateral movement.

---

## Data Access & Impact
Access to the exposed share allowed interaction with stored files and directories.

While no privilege escalation occurred, the ability to retrieve internal files demonstrates how:
- Data exposure alone can be damaging
- SMB misconfigurations often act as initial footholds

---

## Key Lessons Learned
- SMB exposure should always be carefully controlled
- Share enumeration is a high-value reconnaissance step
- Anonymous access is rarely justified
- Internal file shares are frequent sources of sensitive information

---

## Defensive Takeaways
- Disable anonymous SMB access
- Apply least-privilege permissions to shares
- Regularly audit SMB configurations
- Restrict SMB exposure to trusted network segments
