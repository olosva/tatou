#!/bin/bash
set -e  # Exit immediately if any command fails

BRANCH="main"  

#read the GitHub credentials and construct the repo URL
read -p "GitHub username: " GITHUB_USER
read -s -p "GitHub Personal Access Token: " GITHUB_TOKEN

REPO_URL="https://${GITHUB_USER}:${GITHUB_TOKEN}@github.com/olosva/tatou"

cd "$(dirname "$0")"

# Fetch latest commits from remote
git fetch origin "$BRANCH"

# Force local branch to match remote exactly
git reset --hard "origin/$BRANCH"

# Rebuild and start Docker containers
sudo docker compose up --build -d
