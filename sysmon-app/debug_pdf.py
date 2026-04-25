"""
Debug runner: starts the Flask server with debug/traceback errors visible,
then immediately makes a test request to PDF endpoint using urllib (no extra deps needed).
"""
import sys
import os
import io
import json
import traceback

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Import the server functions directly and test PDF endpoint logic
from server import get_system_metrics, get_security_scan, build_pdf_report

# Simulate what the Flask route does
print("=== Simulating /api/report/pdf Flask route ===")
try:
    print("Step 1: get_system_metrics()...")
    metrics_data = get_system_metrics()
    print(f"  OK: timestamp={metrics_data['timestamp'][:19]}")

    print("Step 2: get_security_scan()...")
    scan_data = get_security_scan()
    print(f"  OK: status={scan_data['overall_status']}, score={scan_data['score']}")

    print("Step 3: build_pdf_report()...")
    pdf_bytes = build_pdf_report(metrics_data, scan_data)
    print(f"  OK: {len(pdf_bytes)} bytes")

    print("\n=== Checking data fields that could cause issues ===")
    print(f"  system.version = {repr(metrics_data['system']['version'][:80])}")
    print(f"  system.processor = {repr(metrics_data['system']['processor'][:80])}")
    print(f"  system.os = {repr(metrics_data['system']['os'])}")

    # Detect non-latin-1 characters
    for field_name, val in [
        ("version", metrics_data['system']['version']),
        ("processor", metrics_data['system']['processor']),
        ("os", metrics_data['system']['os']),
        ("hostname", metrics_data['system']['hostname']),
    ]:
        for i, ch in enumerate(str(val)):
            if ord(ch) > 255:
                print(f"  WARNING: Non-latin-1 char in {field_name} at pos {i}: U+{ord(ch):04X} ({repr(ch)})")

    print("\nSUCCESS: No issues found. PDF generation works in direct mode.")
    print("The error must be happening in the running Flask process.")
    print("Check the terminal window where your Flask server is running for the full traceback.")

except Exception as e:
    print(f"\nERROR: {e}")
    traceback.print_exc()
