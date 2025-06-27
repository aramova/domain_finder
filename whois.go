package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"
)

// PerformWhoisLookup performs a WHOIS lookup for the given domain, forcing IPv4.
func PerformWhoisLookup(domain string) (string, error) {
	// First, we need to find the correct WHOIS server for the TLD.
	// We'll use a simple map for common TLDs.
	tld := domain[strings.LastIndex(domain, ".")+1:]
	server, ok := whoisServers[tld]
	if !ok {
		return "", fmt.Errorf("no whois server found for TLD: %s", tld)
	}

	log.Printf("IO: Performing WHOIS lookup for %s via server %s", domain, server)

	// Create a custom dialer that only uses IPv4.
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	// Dial the WHOIS server using our IPv4-only dialer.
	conn, err := dialer.DialContext(context.Background(), "tcp4", server+":43")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Write the domain name to the connection.
	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		return "", err
	}

	// Read the response.
	result, err := ioutil.ReadAll(conn)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

// ParseWhois takes the raw text and populates a structured WhoisData object.
func ParseWhois(rawText string) (*WhoisData, error) {
	parsed, err := whoisparser.Parse(rawText)
	if err != nil {
		return nil, err
	}

	data := &WhoisData{
		RawText: rawText,
	}

	if parsed.Domain != nil {
		data.DomainName = parsed.Domain.Domain
		data.RegistryDomainID = parsed.Domain.ID
		data.NameServers = parsed.Domain.NameServers
		sort.Strings(data.NameServers) // Sort for consistent comparison
		data.ExpiryDate, _ = time.Parse(time.RFC3339, parsed.Domain.ExpirationDate)
		data.CreationDate, _ = time.Parse(time.RFC3339, parsed.Domain.CreatedDate)
		data.UpdatedDate, _ = time.Parse(time.RFC3339, parsed.Domain.UpdatedDate)
	}

	if parsed.Registrar != nil {
		data.Registrar = parsed.Registrar.Name
	}

	if parsed.Registrant != nil {
		data.RegistrantName = parsed.Registrant.Name
		data.RegistrantOrg = parsed.Registrant.Organization
	}

	return data, nil
}


// CompareWhoisRecords compares two WhoisRecord objects and returns a list of
// changes and a boolean indicating if there were any differences.
func CompareWhoisRecords(oldRecord, newRecord *WhoisRecord) ([]string, bool) {
	var differences []string

	// Compare Expiry Date
	if !oldRecord.Data.ExpiryDate.Truncate(24 * time.Hour).Equal(newRecord.Data.ExpiryDate.Truncate(24 * time.Hour)) {
		differences = append(differences, "Expiry Date")
	}

	// Compare Update Date
	if !oldRecord.Data.UpdatedDate.Equal(newRecord.Data.UpdatedDate) {
		differences = append(differences, "Updated Date")
	}

	// Compare Registrant Name
	if oldRecord.Data.RegistrantName != newRecord.Data.RegistrantName {
		differences = append(differences, "Registrant Name")
	}

	// Compare Name Servers
	if !stringSlicesEqual(oldRecord.Data.NameServers, newRecord.Data.NameServers) {
		differences = append(differences, "Name Servers")
	}

	return differences, len(differences) > 0
}

// stringSlicesEqual checks if two string slices are equal, assuming they are sorted.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var whoisServers = map[string]string{
	"com":   "whois.verisign-grs.com",
	"net":   "whois.verisign-grs.com",
	"org":   "whois.pir.org",
	"info":  "whois.afilias.info",
	"biz":   "whois.biz",
	"us":    "whois.nic.us",
	"io":    "whois.nic.io",
	"co":    "whois.nic.co",
	"me":    "whois.nic.me",
	"tv":    "whois.nic.tv",
	"ws":    "whois.website.ws",
	"ca":    "whois.cira.ca",
	"uk":    "whois.nic.uk",
	"de":    "whois.denic.de",
	"jp":    "whois.jprs.jp",
	"au":    "whois.auda.org.au",
	"cn":    "whois.cnnic.cn",
	"fr":    "whois.nic.fr",
	"in":    "whois.registry.in",
	"it":    "whois.nic.it",
	"nl":    "whois.domain-registry.nl",
	"ru":    "whois.tcinet.ru",
	"es":    "whois.nic.es",
	"se":    "whois.iis.se",
	"ch":    "whois.nic.ch",
	"br":    "whois.registro.br",
	"eu":    "whois.eu",
	"be":    "whois.dns.be",
	"at":    "whois.nic.at",
	"pl":    "whois.dns.pl",
	"dk":    "whois.dk-hostmaster.dk",
	"fi":    "whois.fi",
	"no":    "whois.norid.no",
	"cz":    "whois.nic.cz",
	"kr":    "whois.kr",
	"hk":    "whois.hkirc.hk",
	"sg":    "whois.sgnic.sg",
	"tw":    "whois.twnic.net.tw",
	"nz":    "whois.srs.net.nz",
	"za":    "whois.registry.net.za",
	"mx":    "whois.mx",
	"pt":    "whois.dns.pt",
	"tr":    "whois.nic.tr",
	"ua":    "whois.ua",
	"il":    "whois.isoc.org.il",
	"id":    "whois.pandi.or.id",
	"my":    "whois.mynic.my",
	"ph":    "whois.dot.ph",
	"th":    "whois.thnic.co.th",
	"vn":    "whois.vnnic.vn",
	"ae":    "whois.aeda.net.ae",
	"sa":    "whois.nic.net.sa",
	"eg":    "whois.egregistry.eg",
	"ke":    "whois.kenic.or.ke",
	"gh":    "whois.nic.gh",
	"tz":    "whois.tznic.or.tz",
	"ug":    "whois.co.ug",
	"zm":    "whois.zicta.zm",
	"zw":    "whois.zispa.org.zw",
	"ao":    "whois.dns.ao",
	"bw":    "whois.nic.net.bw",
	"cd":    "whois.nic.cd",
	"ci":    "whois.nic.ci",
	"cm":    "whois.netcom.cm",
	"dz":    "whois.nic.dz",
	"et":    "whois.ethiotelecom.et",
	"ga":    "whois.gabon.ga",
	"gm":    "whois.nic.gm",
	"gn":    "whois.psg.com.gn",
	"gq":    "whois.dominio.gq",
	"gw":    "whois.nic.gw",
	"ls":    "whois.co.ls",
	"ly":    "whois.nic.ly",
	"ma":    "whois.iam.net.ma",
	"mg":    "whois.nic.mg",
	"ml":    "whois.dot.ml",
	"mr":    "whois.nic.mr",
	"mu":    "whois.nic.mu",
	"mw":    "whois.nic.mw",
	"mz":    "whois.nic.mz",
	"na":    "whois.na-nic.com.na",
	"ne":    "whois.intnet.ne",
	"ng":    "whois.nic.net.ng",
	"rw":    "whois.ricta.org.rw",
	"sc":    "whois.nic.sc",
	"sd":    "whois.nic.sd",
	"sl":    "whois.nic.sl",
	"sn":    "whois.nic.sn",
	"so":    "whois.nic.so",
	"st":    "whois.nic.st",
	"sz":    "whois.sispa.org.sz",
	"td":    "whois.nic.td",
	"tg":    "whois.nic.tg",
	"tn":    "whois.ati.tn",
}