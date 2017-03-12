package query

import (
	"encoding/json"
	"fmt"

	"log"

	"strings"

	"sort"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/StackExchange/dnscontrol/providers"
	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
)

type queryProvider struct {
	returnError  bool
	targetServer string
}

func init() {
	providers.RegisterDomainServiceProviderType("QUERY", newQuery)
}

func newQuery(map[string]string, json.RawMessage) (providers.DNSServiceProvider, error) {
	qp := &queryProvider{}
	return qp, nil
}

func (q *queryProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	return nil, nil
}

type recordKey struct {
	Type string
	Name string
}

func groupedRecords(recs []*models.RecordConfig) map[recordKey][]*models.RecordConfig {
	m := map[recordKey][]*models.RecordConfig{}
	for _, r := range recs {
		key := recordKey{r.Type, r.Name}
		m[key] = append(m[key], r)
	}
	return m
}

const defaultLookupServer = "8.8.8.8"

func (q *queryProvider) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	nameservers := []string{}
	grouped := groupedRecords(dc.Records)
	for _, r := range grouped[recordKey{"NS", "@"}] {
		nameservers = append(nameservers, r.Target)
	}
	if len(nameservers) == 0 {
		log.Printf("WARNING: No authoritative nameservers found for %s. Defaulting to %s", dc.Name, defaultLookupServer)
		nameservers = append(nameservers, defaultLookupServer)
	}
	var corrections []*models.Correction
	for k, rs := range grouped {
		var rType uint16
		fqdn := rs[0].NameFQDN
		switch k.Type {
		case "A":
			rType = dns.TypeA
		case "CNAME":
			rType = dns.TypeCNAME
		case "TXT":
			rType = dns.TypeTXT
		case "NS":
			rType = dns.TypeNS
		default:
			return nil, fmt.Errorf("Unsupported record type: %s", k.Type)
		}
		msg := &dns.Msg{
			Question: []dns.Question{
				{Qtype: rType, Qclass: dns.ClassINET, Name: fqdn + "."},
			},
		}
		for _, ns := range nameservers {

			resp, err := dns.Exchange(msg, ns+":53")
			if err != nil {
				return nil, fmt.Errorf("Looking up %s %s: %s", k.Type, fqdn, err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				return nil, fmt.Errorf("Looking up %s %s: bad response code: %s", k.Type, fqdn, dns.RcodeToString[resp.Rcode])
			}
			err = diff(rs, resp.Answer, dc.Name)
			if err != nil {
				corrections = append(corrections, &models.Correction{
					Msg: fmt.Sprintf("From %s (%s %s): %s", ns, k.Type, fqdn, err),
					F:   func() error { return nil },
				})
			}
		}
	}
	return corrections, nil
}

func diff(rs []*models.RecordConfig, resp []dns.RR, origin string) error {

	dmp := dump(rs, resp, origin)
	if len(rs) != len(resp) {
		return fmt.Errorf("Expected %d records, but got %d: %s", len(rs), len(resp), dmp)
	}
	//collect targets in both
	expected := []string{}
	got := []string{}
	for _, r := range rs {
		//TODO: in validation, make sure records in same group have same ttl
		expected = append(expected, r.Target)
	}
	ttl := uint32(0)
	for _, rr := range resp {
		if rr.Header().Ttl != ttl && ttl != 0 {
			return fmt.Errorf("Got differing ttls from nameserver: %d and %d both returned %s", rr.Header().Ttl, ttl, dmp)
		}
		ttl = rr.Header().Ttl
		r, _ := rrToRecord(rr, origin, 0)
		got = append(got, r.Target)
	}
	if ttl != rs[0].TTL {
		return fmt.Errorf("Wrong TTL: Got %d, but should be %d %s", ttl, rs[0].TTL, dmp)
	}
	sort.Strings(expected)
	sort.Strings(got)
	e := strings.Join(expected, ", ")
	f := strings.Join(got, ", ")
	if e != f {
		return fmt.Errorf("Record targets don't match. %s", dmp)
	}
	return nil
}

func dump(rs []*models.RecordConfig, resp []dns.RR, origin string) string {
	s := "\nExpected:\n"
	for _, r := range rs {
		s += r.String() + "\n"
	}
	s += "Found:\n"
	for _, rr := range resp {
		r, _ := rrToRecord(rr, origin, 0)
		s += r.String() + "\n"
	}
	return strings.TrimRight(s, "\n")
}

func rrToRecord(rr dns.RR, origin string, replace_serial uint32) (models.RecordConfig, uint32) {
	// Convert's dns.RR into our native data type (models.RecordConfig).
	// Records are translated directly with no changes.
	// If it is an SOA for the apex domain and
	// replace_serial != 0, change the serial to replace_serial.
	// WARNING(tlim): This assumes SOAs do not have serial=0.
	// If one is found, we replace it with serial=1.
	var old_serial, new_serial uint32
	header := rr.Header()
	rc := models.RecordConfig{}
	rc.Type = dns.TypeToString[header.Rrtype]
	rc.NameFQDN = strings.ToLower(strings.TrimSuffix(header.Name, "."))
	rc.Name = strings.ToLower(dnsutil.TrimDomainName(header.Name, origin))
	rc.TTL = header.Ttl
	switch v := rr.(type) {
	case *dns.A:
		rc.Target = v.A.String()
	case *dns.AAAA:
		rc.Target = v.AAAA.String()
	case *dns.CNAME:
		rc.Target = v.Target
	case *dns.MX:
		rc.Target = v.Mx
		rc.Priority = v.Preference
	case *dns.NS:
		rc.Target = v.Ns
	case *dns.SOA:
		old_serial = v.Serial
		if old_serial == 0 {
			// For SOA records, we never return a 0 serial number.
			old_serial = 1
		}
		new_serial = v.Serial
		if rc.Name == "@" && replace_serial != 0 {
			new_serial = replace_serial
		}
		rc.Target = fmt.Sprintf("%v %v %v %v %v %v %v",
			v.Ns, v.Mbox, new_serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.TXT:
		rc.Target = strings.Join(v.Txt, " ")
	default:
		log.Fatalf("Unimplemented zone record type=%s (%v)\n", rc.Type, rr)
	}
	return rc, old_serial
}
