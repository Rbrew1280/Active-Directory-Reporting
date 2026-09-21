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
//Run everything with defaults (90-day inactivity, 14-day password warning)
.\AD-Report.ps1

//Specific reports, custom thresholds and output location
.\AD-Report.ps1 -Reports InactiveUsers,PasswordExpiring -InactiveDays 60 -OutputPath D:\Reports

//Limit to an OU and a specific DC
.\AD-Report.ps1 -SearchBase "OU=Staff,DC=test,DC=com" -Server dc01.test.com
