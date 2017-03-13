package query

import (
	"encoding/json"
	"fmt"

	"log"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/StackExchange/dnscontrol/providers"
	"github.com/StackExchange/dnscontrol/providers/diff"
	"github.com/miekg/dns"
)

type queryProvider struct {
	allNS         bool
	defaultServer string
}

func init() {
	providers.RegisterDomainServiceProviderType("QUERY", newQuery)
}

func newQuery(map[string]string, json.RawMessage) (providers.DNSServiceProvider, error) {
	qp := &queryProvider{allNS: true}
	return qp, nil
}

func (q *queryProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	return nil, nil
}

const defaultLookupServer = "8.8.8.8"

func (q *queryProvider) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	nameservers := []string{}
	grouped := dc.Records.Grouped()
	for _, r := range grouped[models.RecordKey{Type: "NS", Name: "@"}] {
		nameservers = append(nameservers, r.Target)
	}
	if q.defaultServer != "" {
		q.defaultServer = defaultLookupServer
	}
	if len(nameservers) == 0 {
		log.Printf("WARNING: No authoritative nameservers found for %s. Defaulting to %s", dc.Name, q.defaultServer)
		nameservers = append(nameservers, q.defaultServer)
	}
	if !q.allNS {
		nameservers = nameservers[:1]
	}
	fmt.Println(nameservers)
	var corrections []*models.Correction

	for _, ns := range nameservers {
		recs := models.Records{}
		for k, rs := range grouped {
			rr := rs[0].RR()
			fqdn := rs[0].NameFQDN
			msg := &dns.Msg{
				Question: []dns.Question{
					{Qtype: rr.Header().Rrtype, Qclass: dns.ClassINET, Name: fqdn + "."},
				},
			}
			resp, err := dns.Exchange(msg, ns+":53")
			if err != nil {
				return nil, fmt.Errorf("Looking up %s %s: %s", k.Type, fqdn, err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				return nil, fmt.Errorf("Looking up %s %s: bad response code: %s", k.Type, fqdn, dns.RcodeToString[resp.Rcode])
			}
			for _, ans := range resp.Answer {
				rec, err := models.RRToRecord(ans, dc.Name)
				if err != nil {
					return nil, err
				}
				recs = append(recs, rec)
			}
		}
		d := diff.New(dc)
		_, c, dels, mods := d.IncrementalDiff(recs)
		c = append(c, dels...)
		c = append(c, mods...)
		for _, cor := range c {
			corrections = append(corrections, &models.Correction{
				Msg: fmt.Sprintf("From %s: %s", ns, cor),
				F:   func() error { return nil },
			})
		}
	}
	return corrections, nil
}

// func diff(rs []*models.RecordConfig, resp []dns.RR, origin string) error {
// 	dmp := dump(rs, resp, origin)
// 	if len(rs) != len(resp) {
// 		return fmt.Errorf("Expected %d records, but got %d: %s", len(rs), len(resp), dmp)
// 	}
// 	//collect targets in both
// 	expected := []string{}
// 	got := []string{}
// 	for _, r := range rs {
// 		//TODO: in validation, make sure records in same group have same ttl
// 		content := r.Target
// 		if r.Type == "MX" {
// 			content = fmt.Sprintf("%d %s", r.Priority, content)
// 		}
// 		expected = append(expected, content)
// 	}
// 	ttl := uint32(0)
// 	for _, rr := range resp {
// 		if rr.Header().Ttl != ttl && ttl != 0 {
// 			return fmt.Errorf("Got differing ttls from nameserver: %d and %d both returned %s", rr.Header().Ttl, ttl, dmp)
// 		}
// 		ttl = rr.Header().Ttl
// 		r, err := models.RRToRecord(rr, origin)
// 		if err != nil {
// 			return err
// 		}
// 		content := r.Target
// 		if r.Type == "MX" {
// 			content = fmt.Sprintf("%d %s", r.Priority, content)
// 		}
// 		got = append(got, content)
// 	}
// 	if ttl != rs[0].TTL {
// 		return fmt.Errorf("Wrong TTL: Got %d, but should be %d %s", ttl, rs[0].TTL, dmp)
// 	}
// 	sort.Strings(expected)
// 	sort.Strings(got)
// 	e := strings.Join(expected, ", ")
// 	f := strings.Join(got, ", ")
// 	if e != f {
// 		return fmt.Errorf("Record targets don't match. %s", dmp)
// 	}
// 	return nil
// }

// func dump(rs []*models.RecordConfig, resp []dns.RR, origin string) string {
// 	s := "\nExpected:\n"
// 	for _, r := range rs {
// 		s += r.String() + "\n"
// 	}
// 	s += "Found:\n"
// 	for _, rr := range resp {
// 		r, _ := models.RRToRecord(rr, origin)
// 		s += r.String() + "\n"
// 	}
// 	return strings.TrimRight(s, "\n")
// }
