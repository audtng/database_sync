# This is a bash script for when docker containers are to be closed.
# These are the steps 
# git config --global user.name "audtng"
# git config --global user.email "your.email@example.com"
# git add .
# git commit -m "Script: routine automation"
# git push -u origin main
# Picks up env from the exported values in the terminal
# Reduces 5 lines of code and 2 prompts into 1 line of code

#!/bin/bash

# Exit immediately if any command fails

set -e

git config --global user.name "audtng"
git config --global user.email "audtng@example.com"

USERNAME="audtng"

if [ -n "$GITHUB_TOKEN" ]; then
    TOKEN="$GITHUB_TOKEN"
else
    echo -n "Enter token: "
    read -s TOKEN
    echo "" 
fi

git add .

git commit -m "Script: routine automation" || true

git -c credential.helper="!f() { echo \"username=${USERNAME}\"; echo \"password=${TOKEN}\"; }; f" push -u origin main

echo "" 

echo "Successful!"

