# Docker URLs Fix Instructions

## Problem
The GF scan works locally but fails in Docker because the URLs files contain binary content from previous runs.

## Solution
The GF scan now automatically detects and fixes corrupted URLs files. However, for immediate fix in Docker:

### Option 1: Automatic Fix (Recommended)
The GF scan will now automatically detect corrupted URLs files and regenerate them. Just run:
```bash
./main.sh gf scan -d vulnweb.com
```

### Option 2: Manual Fix Script
If needed, run the fix script:
```bash
./fix_docker_urls.sh
```

### Option 3: Regenerate URLs Manually
```bash
# For vulnweb.com
urlfinder -d vulnweb.com -all -silent -pc "${AUTOAR_CONFIG_FILE}" > /app/new-results/vulnweb.com/urls/all-urls.txt

# For fasttest.com  
urlfinder -d fasttest.com -all -silent -pc "${AUTOAR_CONFIG_FILE}" > /app/new-results/fasttest.com/urls/all-urls.txt
```

## What Was Fixed
1. **URL Collection**: Fixed `urlfinder` output redirection to prevent binary content
2. **GF Scan**: Added automatic corruption detection and regeneration
3. **Error Handling**: Better handling of corrupted files

## Expected Results
- **vulnweb.com**: Should find ~13 matches across all GF patterns
- **fasttest.com**: Should find ~190 matches across all GF patterns
- **Exit Code**: 0 (success) instead of 1 (failure)
