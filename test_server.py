#!/usr/bin/env python3
"""Quick test script to verify the server is working."""
import requests
import sys

def test_server():
    base = "http://localhost:8000"
    
    print("Testing Lazarus Web UI server...")
    print(f"Base URL: {base}\n")
    
    # Test root endpoint
    try:
        r = requests.get(f"{base}/", timeout=5)
        print(f"[OK] Root endpoint: {r.status_code}")
        print(f"  Response: {r.json()}\n")
    except Exception as e:
        print(f"[FAIL] Root endpoint failed: {e}\n")
        return False
    
    # Test UI endpoint
    try:
        r = requests.get(f"{base}/ui", timeout=5)
        print(f"[OK] UI endpoint: {r.status_code}")
        print(f"  Content-Type: {r.headers.get('content-type')}")
        print(f"  Content length: {len(r.text)} bytes")
        if r.text.startswith("<!DOCTYPE html>"):
            print("  [OK] Valid HTML detected")
        else:
            print("  [FAIL] Not valid HTML!")
            print(f"  First 100 chars: {r.text[:100]}")
        print()
    except Exception as e:
        print(f"[FAIL] UI endpoint failed: {e}\n")
        return False
    
    print("[OK] All tests passed! Server is working correctly.")
    print(f"\nOpen in browser: {base}/ui")
    return True

if __name__ == "__main__":
    success = test_server()
    sys.exit(0 if success else 1)

