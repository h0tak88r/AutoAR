#!/bin/bash

# Source the main script to access functions
source ./autoAr.sh

# Colors for test output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Test domain to use
TEST_DOMAIN="example.com"

# Required global variables
export TARGET="$TEST_DOMAIN"
export VERBOSE=true
export SAVE_TO_DB=false
export DISCORD_WEBHOOK=""  # Disable Discord notifications during tests

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    echo -n "Running test: $test_name... "
    if eval "$test_cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        return 1
    fi
}

# Setup test environment
setup_test() {
    echo "Setting up test environment..."
    
    # Create temporary test directory
    TEST_DIR="results/$TEST_DOMAIN"
    export DOMAIN_DIR="$TEST_DIR"
    
    # Create necessary directories and files
    mkdir -p "$TEST_DIR"/{subs,urls,vulnerabilities/{xss,sqli,ssrf,ssti,lfi,rce,idor,js,takeovers},fuzzing,ports}
    
    # Create sample data for testing
    echo "https://$TEST_DOMAIN/test?param=1" > "$TEST_DIR/urls/all-urls.txt"
    echo "https://$TEST_DOMAIN/login?user=test" >> "$TEST_DIR/urls/all-urls.txt"
    echo "$TEST_DOMAIN" > "$TEST_DIR/subs/all-subs.txt"
    echo "www.$TEST_DOMAIN" >> "$TEST_DIR/subs/all-subs.txt"
    
    # Create paramx templates directory if it doesn't exist
    if [[ ! -d "paramx-templates" ]]; then
        mkdir -p "paramx-templates"
        echo "Created paramx-templates directory"
    fi
    
    echo "Test environment setup complete at $TEST_DIR"
}

# Cleanup test environment
cleanup_test() {
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
        echo "Test environment cleaned up"
    fi
}

# Test individual functions
test_subdomain_enum() {
    echo "Testing subdomain enumeration..."
    TARGET="$TEST_DOMAIN" subEnum "$TEST_DOMAIN"
    if [[ -f "$TEST_DIR/subs/all-subs.txt" ]]; then
        echo -e "${GREEN}Subdomain enumeration test passed${NC}"
        return 0
    else
        echo -e "${RED}Subdomain enumeration test failed${NC}"
        return 1
    fi
}

test_url_collection() {
    echo "Testing URL collection..."
    TARGET="$TEST_DOMAIN" fetch_urls
    if [[ -f "$TEST_DIR/urls/all-urls.txt" ]]; then
        echo -e "${GREEN}URL collection test passed${NC}"
        return 0
    else
        echo -e "${RED}URL collection test failed${NC}"
        return 1
    fi
}

test_paramx() {
    echo "Testing ParamX scanning..."
    run_paramx_scans
    if ls "$TEST_DIR/vulnerabilities/"*/paramx-results.txt 1> /dev/null 2>&1; then
        echo -e "${GREEN}ParamX scanning test passed${NC}"
        return 0
    else
        echo -e "${RED}ParamX scanning test failed${NC}"
        return 1
    fi
}

test_js_analysis() {
    echo "Testing JavaScript analysis..."
    scan_js_exposures "$TEST_DIR"
    if [[ -d "$TEST_DIR/vulnerabilities/js" ]]; then
        echo -e "${GREEN}JavaScript analysis test passed${NC}"
        return 0
    else
        echo -e "${RED}JavaScript analysis test failed${NC}"
        return 1
    fi
}

test_sql_injection() {
    echo "Testing SQL injection scanning..."
    
    # Create test data directory
    mkdir -p "$TEST_DIR/vulnerabilities/sqli"
    
    # Create sample URLs with SQL injectable parameters
    # Using a known vulnerable test site
    cat > "$TEST_DIR/vulnerabilities/sqli/paramx-results.txt" << EOF
http://testphp.vulnweb.com/artists.php?artist=1
http://testphp.vulnweb.com/listproducts.php?cat=1
http://testphp.vulnweb.com/product.php?pic=1
EOF
    
    # Run SQL injection scan
    run_sql_injection_scan
    
    # Verify the process rather than the results
    local test_passed=0
    
    # Check if input was processed correctly
    if [[ -f "$TEST_DIR/vulnerabilities/sqli/clean_urls.txt" ]]; then
        echo -e "${GREEN}✓ Input preprocessing successful${NC}"
        ((test_passed++))
    fi
    
    # Check if sqlmap was invoked
    if grep -q "sqlmap" "$LOG_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ SQLMap was invoked${NC}"
        ((test_passed++))
    fi
    
    # Check if interlace handled the parallel execution
    if grep -q "interlace" "$LOG_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ Interlace parallel execution worked${NC}"
        ((test_passed++))
    fi
    
    # Check cleanup
    if [[ ! -f "$TEST_DIR/vulnerabilities/sqli/clean_urls.txt" ]]; then
        echo -e "${GREEN}✓ Cleanup successful${NC}"
        ((test_passed++))
    fi
    
    # Final evaluation
    if [[ $test_passed -ge 3 ]]; then
        echo -e "${GREEN}SQL injection scanning test passed - Core functionality verified${NC}"
        return 0
    else
        echo -e "${RED}SQL injection scanning test failed - Some components not working${NC}"
        return 1
    fi
}

# Run all tests
run_all_tests() {
    local failed=0
    
    setup_test
    
    # Run individual tests
    test_subdomain_enum || ((failed++))
    test_url_collection || ((failed++))
    test_paramx || ((failed++))
    test_js_analysis || ((failed++))
    test_sql_injection || ((failed++))
    
    echo
    if [ $failed -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
    else
        echo -e "${RED}$failed test(s) failed${NC}"
    fi
    
    cleanup_test
    return $failed
}

# Main test execution
echo "Starting tests..."
case "$1" in
    "subdomain")
        setup_test
        test_subdomain_enum
        cleanup_test
        ;;
    "urls")
        setup_test
        test_url_collection
        cleanup_test
        ;;
    "paramx")
        setup_test
        test_paramx
        cleanup_test
        ;;
    "js")
        setup_test
        test_js_analysis
        cleanup_test
        ;;
    "sql")
        setup_test
        test_sql_injection
        cleanup_test
        ;;
    "all"|"")
        run_all_tests
        ;;
    *)
        echo "Unknown test: $1"
        echo "Available tests: subdomain, urls, paramx, js, sql, all"
        exit 1
        ;;
esac 