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
	"regexp"
	"strings"
)

func parser(re *regexp.Regexp,group int,data string) ( result []string ) {

	found := re.FindAllStringSubmatch(data, -1)

	if len(found)>0 {
		for _,one := range found {
			if len(one)>=2 && len(one[group])>0 {

				result = appendIfMissing(result,one[group])

			}
		}
	}

	return
}

//Parse uniq name servers from whois
func ParseNameServers(whois string) []string {

	return parser(regexp.MustCompile(`(?i)Name Server:\s+(.*?)(\s|$)`),1,whois)

}

//Parse uniq domain status(codes) from whois
func ParseDomainStatus(whois string) []string {

	return parser(regexp.MustCompile(`(?i)(Domain )?Status:\s+(.*?)(\s|$)`),2,whois)

}

func appendIfMissing(slice []string, i string) []string {

    i = strings.ToLower( i )

    for _, ele := range slice {
        if ele == i {
            return slice
        }
    }

    return append(slice, i)

}
