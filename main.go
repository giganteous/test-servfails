package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/facebookgo/inmem"
	"github.com/miekg/dns"
)

var (
	cache   = inmem.NewLocked(1000)
	unbound = "194.109.9.99:53"
)

func main() {
	flag.StringVar(&unbound, "unbound", unbound, "Nameserver address to use for queries")
	flag.Parse()

	s := NewResolver(unbound)
	scanner := bufio.NewScanner(os.Stdin)
	// Dec 08 15:11:43 resolver-beta.xs4all.net pdns_recursor[17327]: Answer to 0ei-u82fcf4f1-c165-s1512742299-i00000000.eue.dotnxdomain.net|A for [2001:888:0:104::70]:49913 validates as Bogus
	for scanner.Scan() {
		line := scanner.Text()
		start := strings.Index(line, ": Answer to ")
		if start < 0 {
			continue
		}
		if strings.Index(line, "validates as Bogus") < 0 {
			continue
		}
		end := strings.Index(line, " for ")
		if end < 0 {
			continue
		}
		fields := strings.Split(line[start+12:end], "|")
		if len(fields) != 2 {
			continue
		}
		if fields[1] != "A" {
			continue
		}
		s.handle(fields[0])
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading stdin:", err)
	}
}

type Resolver struct {
	c      *dns.Client
	server string
}

func NewResolver(s string) *Resolver {
	return &Resolver{
		c:      new(dns.Client),
		server: s,
	}
}

func (r *Resolver) handle(qname string) {
	qname = dns.Fqdn(qname)

	if _, ok := cache.Get(qname); !ok {
		in := r.lookup(qname)
		cache.Add(qname, in, time.Now().Add(time.Hour))

		if in != nil && in.Rcode != dns.RcodeServerFailure {
			fmt.Printf(">>>>: %s, unbound says ok\n", qname)
		}
	}
}

func (r *Resolver) lookup(qname string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)

	in, _, err := r.c.Exchange(m, r.server)
	if err != nil {
		fmt.Printf("query %s: %s\n", qname, err)
		return nil
	}
	return in
}
