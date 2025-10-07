#!/bin/bash

# AutoAR Release Script
# This script helps create and manage releases

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get current version
CURRENT_VERSION=$(cat VERSION)
echo -e "${BLUE}Current version: ${CURRENT_VERSION}${NC}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}Error: Not in a git repository${NC}"
    exit 1
fi

# Check if there are uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo -e "${YELLOW}Warning: You have uncommitted changes${NC}"
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if secrets are exposed (excluding regex patterns and sample files)
echo -e "${BLUE}Checking for exposed secrets...${NC}"
if grep -r "ghp_\|sk_\|pk_\|AKIA\|AIza\|ya29\|1//" . --exclude-dir=.git --exclude="*.md" --exclude="*.sample.*" --exclude="*.log" --exclude="*.pid" --exclude="*.db" --exclude="new-results" --exclude="autoar.yaml" --exclude-dir="regexes" --exclude-dir="nuclei-templates" --exclude-dir="nuclei_templates" > /dev/null 2>&1; then
    echo -e "${RED}Error: Potential secrets found in files${NC}"
    echo "Please check and remove any exposed secrets before releasing"
    exit 1
fi

# Check if autoar.yaml exists (should be ignored)
if [ -f "autoar.yaml" ]; then
    echo -e "${YELLOW}Warning: autoar.yaml exists (should be in .gitignore)${NC}"
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${GREEN}No secrets found, proceeding with release${NC}"

# Create release tag
echo -e "${BLUE}Creating release tag v${CURRENT_VERSION}...${NC}"
git tag -a "v${CURRENT_VERSION}" -m "Release v${CURRENT_VERSION} - Enhanced Security & S3 Support"

# Push changes and tags
echo -e "${BLUE}Pushing changes and tags...${NC}"
git push origin master
git push origin "v${CURRENT_VERSION}"

echo -e "${GREEN}Release v${CURRENT_VERSION} created successfully!${NC}"
echo -e "${BLUE}Next steps:${NC}"
echo "1. Create a GitHub release with the tag v${CURRENT_VERSION}"
echo "2. Update the changelog with any additional notes"
echo "3. Consider updating the version number for the next release"
