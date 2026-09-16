#!/bin/bash
set -e
shopt -s nullglob

# Output folder for the combined JSON files
OUTPUT_DIR="./json"
mkdir -p "$OUTPUT_DIR"

echo "Grouping JSON files by CWE directory..."

# Loop through all directories in the current folder that start with "CWE-"
for DIR in ./CWE-*/; do
    
    # Get just the folder name (e.g., CWE-79)
    CWE_NAME=$(basename "$DIR")
    
    # Load all JSON files in this directory into an array
    JSON_FILES=("$DIR"*.json)
    
    # Check if the array actually contains files
    if [ ${#JSON_FILES[@]} -gt 0 ]; then
        echo "Processing $CWE_NAME..."
        
        # Merge the array of files into a single JSON file
        jq -s '.' "${JSON_FILES[@]}" > "$OUTPUT_DIR/${CWE_NAME}.json"
    else
        echo "Skipping $CWE_NAME (no JSON files found)."
    fi
done

echo "Success! Combined files are saved in $OUTPUT_DIR."
