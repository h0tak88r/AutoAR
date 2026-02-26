#!/bin/bash

API_KEY="Wc_qPs4g7pv2FhadVFfs_sCR83HjQ1Ea"
get_subdomains() {
    domain=$1

    curl -s "https://api.securitytrails.com/v1/domain/$domain/subdomains?children_only=false" \
        -H "accept: application/json" \
        -H "apikey: $API_KEY" |
        jq -r --arg domain "$domain" '.subdomains[] + "." + $domain'
}

process_domain() {
    domain=$1
    echo -e "\e[34m[+] Fetching subdomains for $domain\e[0m"
    get_subdomains "$domain"
}

main() {
    > subs.txt

    if [[ "$1" == "-l" && -f "$2" ]]; then
        while read -r domain; do
            process_domain "$domain"
        done < "$2"
    else
        read -p "Enter domain: " domain
        process_domain "$domain"
    fi | sort -u >> subs.txt
}

main "$@"