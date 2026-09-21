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


# Usage 
Run everything with defaults (90-day inactivity, 14-day password warning)

.\AD-Report.ps1

Specific reports, custom thresholds and output location

.\AD-Report.ps1 -Reports InactiveUsers,PasswordExpiring -InactiveDays 60 -OutputPath D:\Reports

Limit to an OU and a specific DC

.\AD-Report.ps1 -SearchBase "OU=Staff,DC=test,DC=com" -Server dc01.test.com



Each run writes to a timestamped folder under ADReports\. If a single report fails (for example, a privileged group that doesn't exist in a child domain), the script logs the error and carries on with the rest.

#Requirements 
PowerShell 5.1 or later and the ActiveDirectory module (RSAT, or run it on a domain controller but that not recommended).
