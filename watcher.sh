#!/bin/bash

# The definitive list of 54 CWEs for Golang white-box variant analysis
CWES=(
  # --- Path Traversal, Symlinks & File Permissions ---
  "CWE-22" "CWE-23" "CWE-24" "CWE-25" "CWE-29" "CWE-36" 
  "CWE-59" "CWE-73" "CWE-367" "CWE-552" "CWE-732"
  
  # --- Command & Code Injection ---
  "CWE-78" "CWE-88" "CWE-94" "CWE-95" "CWE-96" "CWE-1336"
  
  # --- Cross-Site Scripting (XSS) & CORS ---
  "CWE-79" "CWE-80" "CWE-81" "CWE-83" "CWE-942"
  
  # --- Database & Query Construction (SQL/NoSQL) ---
  "CWE-89" "CWE-564" "CWE-943"
  
  # --- Resource Consumption, Panics & DoS ---
  "CWE-190" "CWE-248" "CWE-400" "CWE-409" "CWE-476" 
  "CWE-770" "CWE-772" "CWE-843" "CWE-1333"
  
  # --- Error Handling ---
  "CWE-252"
  
  # --- Serialization & XML (XXE) ---
  "CWE-502" "CWE-611" "CWE-827"
  
  # --- Auth, Tokens & Hard-coded Credentials ---
  "CWE-259" "CWE-287" "CWE-321" "CWE-347" "CWE-798"
  
  # --- Cryptography, Randomness, TLS & Timing ---
  "CWE-208" "CWE-295" "CWE-327" "CWE-330" "CWE-385"
  
  # --- Open Redirect & SSRF ---
  "CWE-601" "CWE-918"
  
  # --- Concurrency & Goroutines ---
  "CWE-362"
  
  # --- Logging, Format Strings & Data Leakage ---
  "CWE-117" "CWE-134" "CWE-532"
)

# Uncomment and set your token here if it's not already in your environment variables
# export GITHUB_TOKEN="your_github_token"

for cwe in "${CWES[@]}"; do
  echo "================================================="
  echo "Starting watcher for $cwe..."
  echo "================================================="
  
  ./congenial-robot watch --cwes "$cwe"
  
  if [ $? -ne 0 ]; then
    echo "⚠️ Warning: congenial-robot returned an error for $cwe."
  fi
  
  echo "Finished $cwe. Pausing briefly before the next..."
  sleep 2
done

echo "✅ All CWEs processed successfully!"
