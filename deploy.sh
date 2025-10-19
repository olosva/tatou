#!/bin/bash

read -p "GitHub username: " USERNAME
read -s -p "GitHub personal access token: " TOKEN
echo
git pull https://$USERNAME:$TOKEN@github.com/olosva/tatou
sudo docker compose up --build -d

echo "Should be working"
