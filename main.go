package main

import (
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"net"
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

func main() {
	rand.Seed(time.Now().UnixNano())
	dst := "techack.net"
	ns := "202.12.27.33"
	for {
		r := rrsearch(ns, dst, dns.TypeA)
		if len(r.Answer) == 0 {
			rrs := splitRR(r.Ns[rand.Intn(len(r.Ns))])
			fmt.Println(ns + "=>")
			fmt.Printf("\t%s -> %s\n",
				rrs[0],
				rrs[4],
			)
			if strings.Contains(rrs[4], rrs[0]) {
				for _, rr := range r.Extra {
					rrss := splitRR(rr)
					if strings.Compare(rrss[0], rrs[4]) == 0 {
						ns = rrss[4]
						break
					}
				}
			} else {
				ns = rrs[4]
			}
		} else {
			fmt.Println("Answer : " + ns + "=>")
			for _, ans := range r.Answer {
				anss := splitRR(ans)
				fmt.Printf("\t%s -> %s\n",
					dst,
					anss[4],
				)
			}
			return
		}
	}

}
