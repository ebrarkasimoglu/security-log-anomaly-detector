# Security Log Anomaly Detector (Python)

This small Python project checks an authentication log file and looks for users who have too many failed login attempts.  
It’s a simple way to practise working with log files, dictionaries and basic security logic.



## What the script does

- reads a log file (default: `logs/auth.log`)
- expects lines like:

  `2025-11-10 17:33:04 user123 LOGIN_FAILED`

- counts how many times each user has `LOGIN_FAILED`
- marks users as suspicious if they reach a certain limit (default: 5 failed logins)
- prints a short summary and a list of suspicious users to the console

So you get a quick overview of which accounts might be at risk.

