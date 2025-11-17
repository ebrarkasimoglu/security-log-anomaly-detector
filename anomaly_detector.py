#!/usr/bin/env python3
"""
Security Log Anomaly Detector (Python)

Scans an authentication log file for users with an unusually high number
of failed login attempts. Intended as a simple example for log parsing,
event counting and basic security monitoring logic.
"""

import sys
from pathlib import Path
from typing import Dict, Tuple

DEFAULT_LOG_FILE = Path("logs/auth.log")
DEFAULT_FAILED_THRESHOLD = 5


def load_failed_attempts(log_path: Path) -> Tuple[Dict[str, int], int, int]:
    """
    Parse the log file and collect statistics about failed logins.

    Expected line format:
        DATE TIME USER EVENT
    Example:
        2025-11-10 17:33:04 user123 LOGIN_FAILED

    Returns:
        failed_attempts: mapping user -> number of LOGIN_FAILED events
        total_lines: total number of processed lines
        total_failed: total number of LOGIN_FAILED events
    """
    failed_attempts: Dict[str, int] = {}
    total_lines = 0
    total_failed = 0

    with log_path.open(encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                # ignore empty lines
                continue

            parts = line.split()
            if len(parts) < 4:
                # ignore malformed lines
                continue

            user = parts[2]
            event = parts[3].upper()

            if event == "LOGIN_FAILED":
                total_failed += 1
                failed_attempts[user] = failed_attempts.get(user, 0) + 1

    return failed_attempts, total_lines, total_failed


def find_suspicious_users(
    failed_attempts: Dict[str, int],
    threshold: int,
) -> Dict[str, int]:
    """
    Filter users whose number of failed logins is greater than or equal
    to the threshold.
    """
    return {
        user: count
        for user, count in failed_attempts.items()
        if count >= threshold
    }


def print_summary(
    log_path: Path,
    failed_attempts: Dict[str, int],
    total_lines: int,
    total_failed: int,
    threshold: int,
) -> None:
    """
    Print a concise summary of the analysis to stdout.
    """
    suspicious = find_suspicious_users(failed_attempts, threshold)

    print("=== Security Log Anomaly Detector (Python) ===\n")
    print(f"Log file: {log_path}")
    print(f"Total lines: {total_lines}")
    print(f"Total failed logins: {total_failed}")
    print(f"Users with at least one failed login: {len(failed_attempts)}")
    print(f"Threshold for anomaly: {threshold} failed logins\n")

    if not suspicious:
        print("No suspicious users found based on the current threshold.")
        return

    print("Suspicious users:")
    for user, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
        print(f" - {user} ({count} failed logins)")


def parse_args(argv):
    """
    Parse command line arguments.

    Usage:
        python anomaly_detector.py [log_path] [threshold]

    Both parameters are optional. If not provided, defaults are used.
    """
    # log path
    if len(argv) >= 2:
        log_path = Path(argv[1])
    else:
        log_path = DEFAULT_LOG_FILE

    # threshold
    if len(argv) >= 3:
        try:
            threshold = int(argv[2])
        except ValueError:
            print(f"Invalid threshold value: {argv[2]!r}. Using default: {DEFAULT_FAILED_THRESHOLD}.")
            threshold = DEFAULT_FAILED_THRESHOLD
    else:
        threshold = DEFAULT_FAILED_THRESHOLD

    return log_path, threshold


def main() -> None:
    log_path, threshold = parse_args(sys.argv)

    if not log_path.exists():
        print(f"Log file not found: {log_path}")
        sys.exit(1)

    failed_attempts, total_lines, total_failed = load_failed_attempts(log_path)
    print_summary(log_path, failed_attempts, total_lines, total_failed, threshold)


if __name__ == "__main__":
    main()
