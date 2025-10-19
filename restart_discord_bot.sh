#!/bin/bash
# Script to restart the Discord bot with updated commands

echo "🔄 Restarting Discord Bot with New Database Commands"
echo "=================================================="

# Check if bot is running
if pgrep -f discord_bot.py > /dev/null; then
    echo "✅ Discord bot is currently running"
    echo "⚠️  You need to restart the bot to see the new commands"
    echo ""
    echo "To restart the bot:"
    echo "1. Stop the current bot process (if running in Docker, restart the container)"
    echo "2. Or run: pkill -f discord_bot.py && python3 /home/sallam/AutoAR/discord_bot.py &"
    echo ""
    echo "New commands that will be available after restart:"
    echo "• /db_domains_delete - Delete domain and all related data"
    echo "• /db_stats - Show database statistics"
    echo "• /db_cleanup - Clean up old data from database"
    echo "• /db_subdomains_all - List all subdomains from all domains"
    echo "• /db_js_list - List JS files for domain from database"
    echo ""
    echo "The /help_autoar command will also be fixed after restart."
else
    echo "❌ Discord bot is not running"
    echo "Starting Discord bot..."
    cd /home/sallam/AutoAR
    nohup python3 discord_bot.py > bot.log 2>&1 &
    echo "✅ Discord bot started in background"
    echo "Check bot.log for logs"
fi
