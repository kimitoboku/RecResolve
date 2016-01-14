package main

import (
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

func rrsearch(ns string, q string, t uint16) *dns.Msg {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(q), t)

	r, _, err := c.Exchange(m, net.JoinHostPort(ns, "53"))

	if err != nil {
		fmt.Println(err.Error())
		panic("rrsearch Error")
	}
	return r
}

func splitRR(rr dns.RR) []string {
	rrary := strings.SplitN(rr.String(), "\t", 5)
	return rrary
}

func setNS(rrs []string, r *dns.Msg) (string, string) {
	var ns string
	typ := "A"

	if strings.Contains(rrs[4], rrs[0]) {
		for _, rr := range r.Extra {
			rrss := splitRR(rr)
			if strings.Compare(rrss[0], rrs[4]) == 0 {
				ns = rrss[4]
				typ = rrss[3]
			}
		}
	} else {
		ns = rrs[4]
	}

	return ns, typ
}

func recRsolve(dst, ns string, n int) string {
	var tab string
	for i := 0; i < n; i++ {
		tab = tab + "\t"
	}
	rand.Seed(time.Now().UnixNano())
	for {
		checkNS, _ := regexp.MatchString("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", ns)
		if checkNS == false {
			ns = recRsolve(ns, "202.12.27.33", n+1)
		}
		r := rrsearch(ns, dst, dns.TypeA)
		if len(r.Answer) == 0 {
			rrs := splitRR(r.Ns[rand.Intn(len(r.Ns))])
			nss, typ := setNS(rrs, r)
			for strings.Compare(typ, "AAAA") == 0 {
				rrs := splitRR(r.Ns[rand.Intn(len(r.Ns))])
				nss, typ = setNS(rrs, r)
			}
			ns = nss
			fmt.Println(tab + ns + "=>")
			fmt.Printf(tab+"\t%s -> %s\n",
				rrs[0],
				rrs[4],
			)

		} else {
			fmt.Println(tab + "Answer : " + ns + "=>")
			var ip string
			for _, ans := range r.Answer {
				anss := splitRR(ans)
				fmt.Printf(tab+"\t%s -> %s\n",
					dst,
					anss[4],
				)
				ip = anss[4]
			}
			return ip
		}
	}
}

func main() {
	dst := os.Args
	recRsolve(dst[1], "202.12.27.33", 0)
}
