#!/bin/bash
# Script to fix corrupted URLs files in Docker

echo "Fixing corrupted URLs files in Docker..."

# Fix vulnweb.com URLs
if [[ -f "/app/new-results/vulnweb.com/urls/all-urls.txt" ]]; then
    echo "Fixing vulnweb.com URLs..."
    
    # Backup corrupted file
    mv "/app/new-results/vulnweb.com/urls/all-urls.txt" "/app/new-results/vulnweb.com/urls/all-urls-corrupted.txt"
    
    # Regenerate clean URLs
    if command -v urlfinder >/dev/null 2>&1; then
        urlfinder -d vulnweb.com -all -silent -pc "${AUTOAR_CONFIG_FILE}" > "/app/new-results/vulnweb.com/urls/all-urls.txt" 2>/dev/null
        echo "Regenerated vulnweb.com URLs: $(wc -l < /app/new-results/vulnweb.com/urls/all-urls.txt) lines"
    else
        echo "urlfinder not found, cannot regenerate URLs"
    fi
fi

# Fix fasttest.com URLs if needed
if [[ -f "/app/new-results/fasttest.com/urls/all-urls.txt" ]]; then
    echo "Checking fasttest.com URLs..."
    if head -1 "/app/new-results/fasttest.com/urls/all-urls.txt" | grep -q "Binary file"; then
        echo "Fixing fasttest.com URLs..."
        mv "/app/new-results/fasttest.com/urls/all-urls.txt" "/app/new-results/fasttest.com/urls/all-urls-corrupted.txt"
        
        if command -v urlfinder >/dev/null 2>&1; then
            urlfinder -d fasttest.com -all -silent -pc "${AUTOAR_CONFIG_FILE}" > "/app/new-results/fasttest.com/urls/all-urls.txt" 2>/dev/null
            echo "Regenerated fasttest.com URLs: $(wc -l < /app/new-results/fasttest.com/urls/all-urls.txt) lines"
        fi
    else
        echo "fasttest.com URLs file is clean"
    fi
fi

echo "URLs file fix completed!"
