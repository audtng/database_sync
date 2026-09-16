#The purpose of this script is to copy the json files from the database_sync folder to the rulegen folder and push
#the info

#!/bin/bash
# Exit immediately if any command fails on the host

 set -e

# ==========================================
# Configuration Variables (Host Side)
# ==========================================
 TARGET_DIR="workspace/gh"
 CONTAINER_NAME="jumpbox"
 USERNAME="audtng"     
 REPO_URL="github.com/audtng/rulegen.git"
 REPO_NAME="rulegen"
 SCRIPT="push.sh"

 
 cd "../"

 echo "[Container] Cloning the repository..."
 git clone "https://${USERNAME}:${GITHUB_TOKEN}@${REPO_URL}" "/workspace/${REPO_NAME}"

 cd "/workspace/database_sync"
 echo "$(pwd)"
 cp "json" "-r" "../rulegen"
 cd "../rulegen"
 echo "[Container] Running ${SCRIPT}..."
 bash "${SCRIPT}"

 echo "Copying complete"
 
