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
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

type Whois struct {
	raw string
}

//Simple connection to whois servers with default timeout 5 sec
func GetWhois(domain string) (Whois, error) {

	return GetWhoisTimeout(domain, time.Second*5)

}

//Connection to whois servers with various time.Duration
func GetWhoisTimeout(domain string, timeout time.Duration) (result Whois, err error) {

	var (
		parts      []string
		zone       string
		buffer     []byte
		connection net.Conn
	)

	parts = strings.Split(domain, ".")
	if len(parts) < 2 {
		err = fmt.Errorf("Domain(%s) name is wrong!", domain)
		return
	}
	//last part of domain is zome
	zone = parts[len(parts)-1]

	server, ok := servers[zone]

	if !ok {
		err = fmt.Errorf("No such server for zone %s. Domain %s.", zone, domain)
		return
	}

	connection, err = net.DialTimeout("tcp", net.JoinHostPort(server, "43"), timeout)

	if err != nil {
		//return net.Conn error
		return
	}

	defer connection.Close()

	connection.Write([]byte("" + domain + "\r\n"))

	buffer, err = ioutil.ReadAll(connection)

	if err != nil {
		return
	}

	result = Whois{raw: string(buffer)}

	return
}
