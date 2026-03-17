package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var (
	inputUrl                   *string
	inputFilePath              *string
	filterLevel                *string
	outputFilePath             *string
	filterTLD                  *bool
	top                        *int
	topDomainsPerLevel         = make(map[int]*map[string]int)
	topDomainsPerLevelFiltered = make(map[int][]string)
)

func fail(text string) {
	fmt.Fprintln(os.Stderr, text)
	os.Exit(1)
}

func check(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func parseFilter(filter string) (int, int) {
	if filter == "" {
		return -1, -1
	}
	vMin := -1
	vMax := -1
	var err error
	minMax := strings.Split(filter, ":")
	if len(minMax) == 1 {
		vMin, err = strconv.Atoi(minMax[0])
		vMax = vMin
		check(err)
	} else if len(minMax) == 2 {
		if minMax[0] != "" {
			vMin, err = strconv.Atoi(minMax[0])
			check(err)
		}
		if minMax[1] != "" {
			vMax, err = strconv.Atoi(minMax[1])
			check(err)
		}
	} else {
		fail("Invalid filter value: " + filter)
	}
	return vMin, vMax
}

func writeResults(domains *[]string) {
	_, err := os.Create(*outputFilePath)
	check(err)

	if len(*domains) > 0 {
		file, _ := os.OpenFile(*outputFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		defer file.Close()
		writer := bufio.NewWriter(file)
		for _, domain := range *domains {
			_, _ = fmt.Fprintln(writer, domain)
		}
		_ = writer.Flush()
	}
}

func parseUrl(rawUrl string, lMin, lMax int) []string {
	domains := make([]string, 0)
	if !strings.HasPrefix(rawUrl, "http") {
		rawUrl = "http://" + rawUrl
	}
	u, err := url.Parse(rawUrl)
	if err != nil {
		return domains
	}

	domainLevels := strings.Split(u.Host, ".")

	suffixes := make([]string, 0)
	eTLD, icann := publicsuffix.PublicSuffix(u.Host)
	if icann {
		if eTLD != u.Host {
			suffixes = append(suffixes, eTLD)
		}
	}

	if len(suffixes) > 0 {
		sort.Slice(suffixes, func(i, j int) bool {
			return len(suffixes[i]) > len(suffixes[j])
		})
		tld := suffixes[0]
		tldLength := strings.Count(tld, ".") + 1
		domainLevels = domainLevels[:len(domainLevels)-tldLength]
		domainLevels = append(domainLevels, tld)
	}

	if lMin <= len(domainLevels) {
		if lMax == -1 || lMax > len(domainLevels) {
			lMax = len(domainLevels)
		}
		for i := lMax; i > 0 && i >= lMin; i-- {
			domain := strings.Join(domainLevels[len(domainLevels)-i:], ".")
			if domain != "" {
				domains = append(domains, domain)
				if *top > 0 {
					if topDomainsPerLevel[i] == nil {
						levelMap := make(map[string]int)
						topDomainsPerLevel[i] = &levelMap
					}
					levelMap := topDomainsPerLevel[i]
					(*levelMap)[domain] = (*levelMap)[domain] + 1
				}
			}
		}
	}

	return domains
}

func main() {
	inputUrl = flag.String("i", "", "Input url or domain")
	inputFilePath = flag.String("if", "", "Input file path, one url/domain per line.")
	filterLevel = flag.String("f", "", "Filter domain level. "+
		"Use python slice notation to select range. \nExample input: foo.bar.baz.tld \n"+
		"  \033[3m-f 3  \033[0m    bar.baz.tld \n"+
		"  \033[3m-f 3: \033[0m    bar.baz.tld, foo.bar.baz.tld\n"+
		"  \033[3m-f 2:4\033[0m    baz.tld, bar.baz.tld\n"+
		"  \033[3m-f :3 \033[0m    tld, baz.tld")
	outputFilePath = flag.String("o", "", "Output file path, optional")
	//filterTLD = flag.Bool("t", true, "Filter invalid domains according to Mozilla's publicsuffix list.")
	top = flag.Int("top", 0, "Only consider top X subdomains of a certain level and return all their subdomains")

	flag.Parse()

	// set filterTLD to true by default while removing the flag
	t := true
	filterTLD = &t

	inputUrls := make([]string, 0)
	if *inputUrl != "" {
		inputUrls = append(inputUrls, *inputUrl)
	}
	if *inputFilePath != "" {
		inputFile, err := os.Open(*inputFilePath)
		check(err)
		defer inputFile.Close()
		scanner := bufio.NewScanner(inputFile)
		for scanner.Scan() {
			inputUrls = append(inputUrls, scanner.Text())
		}
	}

	// TODO: Consider program main execution to be in goroutine.
	if *inputUrl == "" && *inputFilePath == "" {
		// Let's get input from Stdin

		// Check for stdin input
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Fprintln(os.Stderr, "No domains detected. Hint: cat domains.txt | dsieve -f 2")
			os.Exit(1)
		}

		sc := bufio.NewScanner(os.Stdin)

		for sc.Scan() {
			inputUrls = append(inputUrls, sc.Text())
		}

	}

	// Leaving this in, for incase all/any input process gives un Zero URLs.
	if len(inputUrls) == 0 {
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nError: No input.")
		os.Exit(1)
	}

	lMin, lMax := parseFilter(*filterLevel)
	domainMap := make(map[string]bool)
	domains := make([]string, 0)
	for _, inputURL := range inputUrls {
		for _, domain := range parseUrl(inputURL, lMin, lMax) {
			if _, dup := domainMap[domain]; !dup {
				eTLD, icann := publicsuffix.PublicSuffix(domain)
				if *filterTLD {
					if icann {
						if eTLD != domain {
							if *top == 0 {
								fmt.Println(domain)
							}
							domainMap[domain] = true
							domains = append(domains, domain)
						}
					}
				} else {
					if *top == 0 {
						fmt.Println(domain)
					}
					domainMap[domain] = true
					domains = append(domains, domain)
				}
			}
		}
	}

	if *top > 0 {
		if lMax < 0 {
			for lvl := range topDomainsPerLevel {
				if lvl > lMax {
					lMax = lvl
				}
			}
		}
		for i := lMax; i > 0 && i >= lMin; i-- {
			domainsForLevel := make([]string, 0)
			levelMap := topDomainsPerLevel[i]
			if levelMap == nil {
				continue
			}
			for _, domain := range domains {
				if _, ok := (*levelMap)[domain]; ok {
					domainsForLevel = append(domainsForLevel, domain)
				}
			}
			if len(domainsForLevel) > 0 {
				sort.Slice(domainsForLevel, func(i, j int) bool {
					return (*levelMap)[domainsForLevel[i]] > (*levelMap)[domainsForLevel[j]]
				})
				if len(domainsForLevel) >= *top {
					domainsForLevel = domainsForLevel[:*top]
				}
				topDomainsPerLevelFiltered[i] = domainsForLevel
			}
		}

		maxLevel := 0
		for level := range topDomainsPerLevelFiltered {
			if level > maxLevel {
				maxLevel = level
			}
		}

		if strings.Contains(*filterLevel, ":") {
			if strings.HasSuffix(*filterLevel, ":") {
				lvl, err := strconv.Atoi(strings.TrimSuffix(*filterLevel, ":"))
				if err != nil {
					check(err)
				}
				maxLevel = lvl
			} else {
				split := strings.Split(*filterLevel, ":")
				lvl, err := strconv.Atoi(split[len(split)-1])
				if err != nil {
					check(err)
				}
				maxLevel = lvl - 1
			}
			filteredDomains := make([]string, 0)
			for _, inputURL := range inputUrls {
				for _, d := range topDomainsPerLevelFiltered[maxLevel] {
					if strings.HasSuffix(inputURL, d) {
						filteredDomains = append(filteredDomains, inputURL)
						fmt.Println(inputURL)
					}
				}
			}
			domains = filteredDomains
		} else {
			for _, d := range topDomainsPerLevelFiltered[maxLevel] {
				fmt.Println(d)
			}
			domains = topDomainsPerLevelFiltered[maxLevel]
		}
	}

	if *outputFilePath != "" && len(domains) > 0 {
		writeResults(&domains)
	}
}
