package main

/*

Requirements:
* Each TXT record needs to be 255 bytes or less.
* The first TXT record needs to be shorter than 255, the amount
  shorter should be user-configurable.
* The "native" SPF record will be stored as a TXT record in orig-spf.stackoverflow.com.
* The flattener will read the "native" SPF record and generate spf-flattened.js which is "var

dnscontrol vdig stackoverflow.com txt (reads the config, outputs the txt record for stackoverflow.com based on the )

1. The "native SPF" record is stored in dnsconfig.js:

D("stackoverflow.com", ....)
   TXT("orig-spf", "v=spf1 ip4:198.252.206.0/24 ip4:192.111.0.0/24 include:_spf.google.com include:mailgun.org include:spf-basic.fogcreek.com include:mail.zendesk.com include:servers.mcsv.net include:sendgrid.net include:spf.mtasv.net ~all"



*/

import (
	"fmt"
	"strings"
)

var unrollWhitelist = map[string]bool{
	"include:spf-basic.fogcreek.com": true,
	"include:_spf.google.com":        true,
}

func lookupSpf(s string) (string, error) {
	// fmt.Printf("DEBUG: lookupSpf(%+s)\n", s)
	switch s {
	case "spf-basic.fogcreek.com":
		return "v=spf1 ip4:64.34.80.172 -all", nil
	case "_spf.google.com":
		return "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all", nil
	default:
		return "", fmt.Errorf("Failed DNS lookup")
	}
}

func unroll1(s string) []string {
	// fmt.Printf("DEBUG: unroll1(%+s)\n", s)
	var results []string
	for _, f := range strings.Fields(s) {
		if f == "v=spf1" {
			// ignore
		} else if strings.HasPrefix(f, "ip4:") {
			results = append(results, f)
		} else if strings.HasPrefix(f, "ip6:") {
			results = append(results, f)
		} else if strings.HasPrefix(f, "-all") {
			// ignore
		} else if strings.HasPrefix(f, "-all") {
			// ignore
		} else if strings.HasPrefix(f, "include:") {
			if _, ok := unrollWhitelist[f]; ok {
				r, err := lookupSpf(f[8:])
				if err == nil {
					results = append(results, unroll1(r)...)
				} else {
					results = append(results, r)
				}
			} else {
				results = append(results, f)
			}
		} else {
			results = append(results, f)
		}
	}
	// fmt.Printf("DEBUG: RET unroll1(%+s) returns %+s\n", s, results)
	return results
}

func main() {
	fmt.Println("vim-go")

	spfOriginal := "v=spf1 ip4:198.252.206.0/24 ip4:192.111.0.0/24 include:_spf.google.com include:mailgun.org include:spf-basic.fogcreek.com include:mail.zendesk.com include:servers.mcsv.net include:sendgrid.net include:spf.mtasv.net ~all"

	var results []string
	results = append(results, "v=spf1")
	results = append(results, unroll1(spfOriginal)...)
	results = append(results, "~all")
	fmt.Printf("Input:\n%s\n\n", spfOriginal)
	fmt.Printf("Result:\n%s\n", strings.Join(results, " "))

}
