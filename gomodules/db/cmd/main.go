package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/h0tak88r/AutoAR/gomodules/db"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [args...]\n", os.Args[0])
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "init-schema":
		if err := db.Init(); err != nil {
			log.Fatalf("Failed to initialize database: %v", err)
		}
		if err := db.InitSchema(); err != nil {
			log.Fatalf("Failed to initialize schema: %v", err)
		}
		fmt.Println("[OK] Database schema initialized")

	case "check-connection":
		if err := db.Init(); err != nil {
			log.Fatalf("Failed to connect: %v", err)
		}
		fmt.Println("[OK] Database connection successful")

	case "insert-domain":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s insert-domain <domain>\n", os.Args[0])
			os.Exit(1)
		}
		domain := os.Args[2]
		if err := db.Init(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
			os.Exit(1)
		}
		domainID, err := db.InsertOrGetDomain(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to insert/get domain: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(domainID)

	case "batch-insert-subdomains":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s batch-insert-subdomains <domain> <file> [is_live]\n", os.Args[0])
			os.Exit(1)
		}
		domain := os.Args[2]
		filePath := os.Args[3]
		isLive := false
		if len(os.Args) >= 5 {
			isLive = os.Args[4] == "true" || os.Args[4] == "1" || os.Args[4] == "TRUE"
		}

		// Read subdomains from file
		file, err := os.Open(filePath)
		if err != nil {
			log.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()

		var subdomains []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				subdomains = append(subdomains, line)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Failed to read file: %v", err)
		}

		if err := db.Init(); err != nil {
			log.Fatalf("Failed to initialize database: %v", err)
		}

		if err := db.BatchInsertSubdomains(domain, subdomains, isLive); err != nil {
			log.Fatalf("Failed to batch insert subdomains: %v", err)
		}

	case "insert-subdomain":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s insert-subdomain <domain> <subdomain> [is_live] [http_url] [https_url] [http_status] [https_status]\n", os.Args[0])
			os.Exit(1)
		}
		domain := os.Args[2]
		subdomain := os.Args[3]
		isLive := false
		httpURL := ""
		httpsURL := ""
		httpStatus := 0
		httpsStatus := 0
		
		if len(os.Args) >= 5 {
			isLive = os.Args[4] == "true" || os.Args[4] == "1" || os.Args[4] == "TRUE"
		}
		if len(os.Args) >= 6 {
			httpURL = os.Args[5]
		}
		if len(os.Args) >= 7 {
			httpsURL = os.Args[6]
		}
		if len(os.Args) >= 8 {
			fmt.Sscanf(os.Args[7], "%d", &httpStatus)
		}
		if len(os.Args) >= 9 {
			fmt.Sscanf(os.Args[8], "%d", &httpsStatus)
		}

		if err := db.Init(); err != nil {
			log.Fatalf("Failed to initialize database: %v", err)
		}

		if err := db.InsertSubdomain(domain, subdomain, isLive, httpURL, httpsURL, httpStatus, httpsStatus); err != nil {
			log.Fatalf("Failed to insert subdomain: %v", err)
		}

	case "insert-js-file":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s insert-js-file <domain> <js_url> [content_hash]\n", os.Args[0])
			os.Exit(1)
		}
		domain := os.Args[2]
		jsURL := os.Args[3]
		contentHash := ""
		if len(os.Args) >= 5 {
			contentHash = os.Args[4]
		}

		if err := db.Init(); err != nil {
			log.Fatalf("Failed to initialize database: %v", err)
		}

		if err := db.InsertJSFile(domain, jsURL, contentHash); err != nil {
			log.Fatalf("Failed to insert JS file: %v", err)
		}

	case "insert-keyhack-template":
		if len(os.Args) < 9 {
			fmt.Fprintf(os.Stderr, "Usage: %s insert-keyhack-template <keyname> <command> <method> <url> <header> <body> <notes> <description>\n", os.Args[0])
			os.Exit(1)
		}
		keyname := os.Args[2]
		command := os.Args[3]
		method := os.Args[4]
		url := os.Args[5]
		header := os.Args[6]
		body := os.Args[7]
		notes := os.Args[8]
		description := os.Args[9]

		if err := db.Init(); err != nil {
			log.Fatalf("Failed to initialize database: %v", err)
		}

		if err := db.InsertKeyhackTemplate(keyname, command, method, url, header, body, notes, description); err != nil {
			log.Fatalf("Failed to insert keyhack template: %v", err)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}
}
