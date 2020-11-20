// -------------------------
//
// Copyright 2015, undiabler
//
// git: github.com/undiabler/golang-whois
//
// http://undiabler.com
//
// Released under the Apache License, Version 2.0
//
//--------------------------

package whois

import (
	"bufio"
	"regexp"
	"strings"
)

func parser(re *regexp.Regexp, group int, data string) (result []string) {

	found := re.FindAllStringSubmatch(data, -1)

	if len(found) > 0 {
		for _, one := range found {
			if len(one) >= 2 && len(one[group]) > 0 {
				result = appendIfMissing(result, one[group])
			}
		}
	}

	return
}

//Parse uniq name servers from whois
func ParseNameServers(whois string) []string {
	
	resultNameServers := parser(regexp.MustCompile(`(?i)Name Server:\s+(.*?)(\s|$)`), 1, whois)

	if len(resultNameServers) == 0 {
		var re = regexp.MustCompile(`(?i)(Name servers:\n(?:\s+(?:[a-zA-Z-_\.0-9]+)\n)+)`)
		nameServersString := re.FindString(whois)

		scanner := bufio.NewScanner(strings.NewReader(nameServersString))
		// Read first line, ie. Name Servers:
		scanner.Scan()

		// Iterate over Name Servers
		for scanner.Scan() {
			resultNameServers = append(resultNameServers, strings.TrimSpace(scanner.Text()))
		}

	}
	
	return resultNameServers
}

//Parse uniq domain status(codes) from whois
func ParseDomainStatus(whois string) []string {

	return parser(regexp.MustCompile(`(?i)(Domain )?Status:\s+(.*?)(\s|$)`), 2, whois)

}

func appendIfMissing(slice []string, i string) []string {

	i = strings.ToLower(i)

	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}

	return append(slice, i)

}
