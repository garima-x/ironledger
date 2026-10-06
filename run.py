#!/usr/bin/env python3
"""
IronLedger Launcher - Runs the FastAPI Backend and Serves Cyber Dashboard on Port 8080
"""

import os
import sys
import uvicorn

# Ensure ironledger root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    contract = os.environ.get("SEPOLIA_CONTRACT_ADDRESS", "0x7a36B3DeE1F03287cCE488f2604245F11dF9d78F")

    print("================================================================")
    print(" 🛡️  IRONLEDGER: ICS Digital Forensics & Blockchain Framework")
    print(f" Server starting on http://{host}:{port}")
    print(f" Sepolia Smart Contract Anchor: {contract}")
    print("================================================================")
    uvicorn.run("backend.api:app", host=host, port=port, log_level="info")
