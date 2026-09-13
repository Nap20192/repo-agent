"""Static scanners → Anchors, one scanner per file: gosec, semgrep, osv-scanner, gitleaks run on the host through
process.run_cmd; sarif.py parses SARIF; scan.py runs every applicable scanner concurrently, redacts secrets and merges
duplicates. Ported from git-agent3 internal/adapter/{static,secrets}."""

from scanner.adapter.scanners.osv import OSV_MAX, anchors_from_osv
from scanner.adapter.scanners.sarif import anchors_from_sarif
from scanner.adapter.scanners.scan import ScanResult, run_jobs, scan

__all__ = ["OSV_MAX", "ScanResult", "anchors_from_osv", "anchors_from_sarif", "run_jobs", "scan"]
