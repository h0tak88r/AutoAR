#!/bin/bash
# AutoAR API - cURL Examples
# Collection of example API calls using curl

API_BASE="http://localhost:8000"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}AutoAR API - cURL Examples${NC}"
echo -e "${BLUE}======================================${NC}\n"

# Health Check
echo -e "${GREEN}1. Health Check${NC}"
echo -e "${YELLOW}curl $API_BASE/health${NC}"
curl -s "$API_BASE/health" | jq '.'
echo -e "\n"

# API Root
echo -e "${GREEN}2. API Root / Info${NC}"
echo -e "${YELLOW}curl $API_BASE/${NC}"
curl -s "$API_BASE/" | jq '.'
echo -e "\n"

# Start Subdomain Scan
echo -e "${GREEN}3. Start Subdomain Enumeration${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/subdomains -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
SCAN_RESPONSE=$(curl -s -X POST "$API_BASE/scan/subdomains" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}')
echo "$SCAN_RESPONSE" | jq '.'
SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.scan_id')
echo -e "\n"

# Check Scan Status
if [ ! -z "$SCAN_ID" ] && [ "$SCAN_ID" != "null" ]; then
  echo -e "${GREEN}4. Check Scan Status${NC}"
  echo -e "${YELLOW}curl $API_BASE/scan/$SCAN_ID/status${NC}"
  curl -s "$API_BASE/scan/$SCAN_ID/status" | jq '.'
  echo -e "\n"

  # Wait a bit
  echo -e "${BLUE}Waiting 5 seconds...${NC}\n"
  sleep 5

  # Get Scan Results
  echo -e "${GREEN}5. Get Scan Results${NC}"
  echo -e "${YELLOW}curl $API_BASE/scan/$SCAN_ID/results${NC}"
  curl -s "$API_BASE/scan/$SCAN_ID/results" | jq '.'
  echo -e "\n"

  # Download Results
  echo -e "${GREEN}6. Download Results${NC}"
  echo -e "${YELLOW}curl -O $API_BASE/scan/$SCAN_ID/download${NC}"
  echo "(Skipping actual download in demo)"
  echo -e "\n"
fi

# List All Scans
echo -e "${GREEN}7. List All Scans${NC}"
echo -e "${YELLOW}curl $API_BASE/scans${NC}"
curl -s "$API_BASE/scans" | jq '.'
echo -e "\n"

# Port Scan
echo -e "${GREEN}8. Start Port Scan${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/ports -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/ports" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq '.'
echo -e "\n"

# JavaScript Scan
echo -e "${GREEN}9. Start JavaScript Analysis${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/js -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\", \"subdomain\": \"api.example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/js" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "subdomain": "api.example.com"}' | jq '.'
echo -e "\n"

# Nuclei Vulnerability Scan
echo -e "${GREEN}10. Start Nuclei Vulnerability Scan${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/nuclei -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/nuclei" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq '.'
echo -e "\n"

# Live Hosts Discovery
echo -e "${GREEN}11. Discover Live Hosts${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/livehosts -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/livehosts" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq '.'
echo -e "\n"

# URL Collection
echo -e "${GREEN}12. Collect URLs${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/urls -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/urls" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq '.'
echo -e "\n"

# Technology Detection
echo -e "${GREEN}13. Detect Technologies${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/tech -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/tech" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq '.'
echo -e "\n"

# DNS Takeover Check
echo -e "${GREEN}14. DNS Takeover Check${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/dns-takeover -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/dns-takeover" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq '.'
echo -e "\n"

# S3 Bucket Scan
echo -e "${GREEN}15. S3 Bucket Scan${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/s3 -H 'Content-Type: application/json' -d '{\"bucket\": \"example-bucket\", \"region\": \"us-east-1\"}'${NC}"
curl -s -X POST "$API_BASE/scan/s3" \
  -H "Content-Type: application/json" \
  -d '{"bucket": "example-bucket", "region": "us-east-1"}' | jq '.'
echo -e "\n"

# GitHub Repository Scan
echo -e "${GREEN}16. GitHub Repository Scan${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/github -H 'Content-Type: application/json' -d '{\"repo\": \"owner/repository\"}'${NC}"
curl -s -X POST "$API_BASE/scan/github" \
  -H "Content-Type: application/json" \
  -d '{"repo": "owner/repository"}' | jq '.'
echo -e "\n"

# CNAME Records
echo -e "${GREEN}17. Get CNAME Records${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/cnames -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/cnames" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq '.'
echo -e "\n"

# GF Pattern Matching
echo -e "${GREEN}18. GF Pattern Matching${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/gf -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/gf" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq '.'
echo -e "\n"

# Reflection Scan
echo -e "${GREEN}19. Reflection Vulnerability Scan${NC}"
echo -e "${YELLOW}curl -X POST $API_BASE/scan/reflection -H 'Content-Type: application/json' -d '{\"domain\": \"example.com\"}'${NC}"
curl -s -X POST "$API_BASE/scan/reflection" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq '.'
echo -e "\n"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Examples Complete!${NC}"
echo -e "${BLUE}======================================${NC}"
echo -e "\n${YELLOW}Note: Install 'jq' for pretty JSON output${NC}"
echo -e "${YELLOW}      brew install jq (macOS)${NC}"
echo -e "${YELLOW}      apt install jq (Ubuntu/Debian)${NC}\n"

echo -e "${GREEN}Interactive API Documentation:${NC}"
echo -e "  Swagger UI: ${BLUE}$API_BASE/docs${NC}"
echo -e "  ReDoc:      ${BLUE}$API_BASE/redoc${NC}\n"
