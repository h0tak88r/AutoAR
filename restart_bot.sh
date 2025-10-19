#!/bin/bash
# Script to restart the Discord bot

echo "Restarting Discord bot..."

# Kill existing bot processes
pkill -f discord_bot.py
sleep 2

# Start the bot in background
nohup python3 /app/discord_bot.py > /app/bot.log 2>&1 &

echo "Discord bot restarted. Check /app/bot.log for logs."
