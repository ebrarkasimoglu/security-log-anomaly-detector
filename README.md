# Security Log Anomaly Detector (Java)

This is a small Java console tool that scans an authentication log file and looks for users with an unusually high number of failed login attempts.

The goal is to practice basic log parsing, counting events per user and deriving a simple security signal from it.

---

## How it works

- reads a log file (default: `logs/auth.log`)
- expects lines in the format: `DATE TIME USER EVENT`
  - example: `2025-11-10 17:33:04 user123 LOGIN_FAILED`
- counts `LOGIN_FAILED` events per user
- flags users whose failed logins exceed a given threshold (default: 5)
- prints a short summary and a list of suspicious users

---

## Project structure

```text
security-log-anomaly-detector/
 ├── logs/
 │   └── auth.log
 ├── src/
 │   └── SecurityLogAnomalyDetector.java
 └── README.md
