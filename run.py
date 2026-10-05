#!/usr/bin/env python3
"""
IronLedger Launcher - Runs the FastAPI Backend and Serves Cyber Dashboard on Port 8080
"""

import uvicorn
import os
import sys

# Ensure ironledger root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("================================================================")
    print(" 🛡️  IRONLEDGER: ICS Digital Forensics & Blockchain Framework")
    print(" Server starting on http://localhost:8080")
    print(" Sepolia Smart Contract: 0x7a36B3DeE1F03287cCE488f2604245F11dF9d78F")
    print("================================================================")
    uvicorn.run("backend.api:app", host="0.0.0.0", port=8080, log_level="info")
