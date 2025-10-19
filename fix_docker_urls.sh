#!/bin/bash
# Script to fix corrupted URLs files in Docker

echo "🔧 Fixing corrupted URLs files in Docker..."

# Check if we're in Docker
if [[ -f /.dockerenv ]]; then
    echo "✅ Running in Docker container"
    
    # Fix vulnweb.com URLs
    if [[ -f "/app/new-results/vulnweb.com/urls/all-urls.txt" ]]; then
        echo "🔍 Fixing vulnweb.com URLs file..."
        
        # Backup corrupted file
        mv "/app/new-results/vulnweb.com/urls/all-urls.txt" "/app/new-results/vulnweb.com/urls/all-urls-corrupted.txt"
        
        # Regenerate clean URLs
        echo "📡 Regenerating clean URLs for vulnweb.com..."
        urlfinder -d vulnweb.com -all -silent -pc "${AUTOAR_CONFIG_FILE}" > "/app/new-results/vulnweb.com/urls/all-urls.txt" 2>/dev/null
        
        if [[ -s "/app/new-results/vulnweb.com/urls/all-urls.txt" ]]; then
            echo "✅ Successfully regenerated $(wc -l < /app/new-results/vulnweb.com/urls/all-urls.txt) clean URLs"
        else
            echo "❌ Failed to regenerate URLs"
            exit 1
        fi
    fi
    
    # Fix fasttest.com URLs if needed
    if [[ -f "/app/new-results/fasttest.com/urls/all-urls.txt" ]]; then
        echo "🔍 Checking fasttest.com URLs file..."
        if file "/app/new-results/fasttest.com/urls/all-urls.txt" | grep -q "data"; then
            echo "🔧 Fixing fasttest.com URLs file..."
            mv "/app/new-results/fasttest.com/urls/all-urls.txt" "/app/new-results/fasttest.com/urls/all-urls-corrupted.txt"
            urlfinder -d fasttest.com -all -silent -pc "${AUTOAR_CONFIG_FILE}" > "/app/new-results/fasttest.com/urls/all-urls.txt" 2>/dev/null
            echo "✅ Fixed fasttest.com URLs file"
        else
            echo "✅ fasttest.com URLs file is clean"
        fi
    fi
    
    echo "🎉 URLs files fixed successfully!"
    
else
    echo "❌ This script should be run inside Docker container"
    exit 1
fi
