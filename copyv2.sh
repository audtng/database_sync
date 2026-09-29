#!/bin/bash

# Configuration
SOURCE_DIR="./CWE-287"
DEST_DIR="../rulegen/CWE-287"
TRACKING_FILE="$DEST_DIR/.copied_files_db.txt"

# Ensure directories exist
if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory $SOURCE_DIR does not exist."
    exit 1
fi

mkdir -p "$DEST_DIR"
touch "$TRACKING_FILE"

# Track if any new files were copied during this run
copied_any=false

# Find all files and process them one by one (handles spaces safely)
find "$SOURCE_DIR" -type f -print0 | while IFS= read -r -d '' src_file; do
    
    # Calculate unique SHA-256 hash of the file
    file_hash=$(sha256sum "$src_file" | awk '{print $1}')
    
    # Check if this hash is already in our tracking database
    if grep -q "$file_hash" "$TRACKING_FILE"; then
        echo "Skipping (Already Copied): $(basename "$src_file")"
        continue # Skip to the next file in the list
    else
        # Determine relative path to maintain folder structure
        rel_path="${src_file#$SOURCE_DIR/}"
        dest_file="$DEST_DIR/$rel_path"
        
        # Create subdirectories in destination if they don't exist
        mkdir -p "$(dirname "$dest_file")"
        
        # Copy the file
        if cp "$src_file" "$dest_file"; then
            echo "Successfully Copied: $rel_path"
            # Log the hash and file path to the database
            echo "$file_hash:$rel_path" >> "$TRACKING_FILE"
            copied_any=true
        else
            echo "Error: Failed to copy $rel_path"
            exit 1 # Exit with an error if the copy fails
        fi
    fi
done

# Check if anything was processed
if [ "$copied_any" = false ]; then
    echo "All files are already up to date. No files to copy."
fi
