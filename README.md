# Active-Directory-Reporting
A read-only PowerShell script that reports Active Directory
Reports it generates (each as a CSV, plus one combined HTML summary):

Inactive users: enabled accounts with no logon in N days
Disabled users
Password never expires: enabled accounts only
Passwords expiring soon: within a configurable window
Locked-out accounts
Privileged group members: Domain Admins, Enterprise Admins, Schema Admins, Administrators and others, resolved recursively
Stale computers
Empty groups
