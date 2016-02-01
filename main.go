package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/codegangsta/cli"
	"github.com/miekg/dns"
)

const (
	Version = "0.0.3"
)

var (
	root  string
	debug bool
)

func rrsearch(ns string, q string, t uint16) *dns.Msg {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(q), t)

	if debug {
		log.Printf("NS %v,Question %v\n", ns, q)
	}
	r, _, err := c.Exchange(m, net.JoinHostPort(ns, "53"))
	if debug {
		log.Printf("NS %v,Response %v\n", ns, r.String())
	}
	if err != nil {
		fmt.Println(err.Error())
		panic("rrsearch Error")
	}
	return r
}

func splitRR(rr dns.RR) []string {
	if debug {
		log.Printf("RR %v\n", rr.String())
	}
	rrary := strings.SplitN(rr.String(), "\t", 5)
	return rrary
}

func setNS(rrs []string, r *dns.Msg, qns string) (string, string) {
	if debug {
		log.Printf("RRS %v,DNS Message %v Qns %v\n", rrs, r.String(), qns)
	}

	var ns string
	typ := "A"

	if strings.Contains(rrs[4], rrs[0]) || strings.Compare(qns, root) == 0 {
		for _, rr := range r.Extra {
			rrss := splitRR(rr)
			if strings.Compare(rrss[3], "AAAA") == 0 {
				break
			}
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

func noRecRsolve(dst, ns string) string {
	rand.Seed(time.Now().UnixNano())
	for {
		r := rrsearch(ns, dst, dns.TypeA)
		if len(r.Answer) == 0 {
			rrs := splitRR(r.Ns[rand.Intn(len(r.Ns))])
			nss, typ := setNS(rrs, r, ns)
			for strings.Compare(typ, "AAAA") == 0 {
				if debug {
					log.Printf("Type %v\n", typ)
				}
				rrs := splitRR(r.Ns[rand.Intn(len(r.Ns))])
				nss, typ = setNS(rrs, r, ns)
			}
			fmt.Println(ns + "=>")
			fmt.Printf("\t%s -> %s\n",
				rrs[0],
				rrs[4],
			)
			if strings.Compare(rrs[0], ".") == 0 {
				fmt.Println("Domain Name Not found")
				os.Exit(1)
			}
			ns = nss
		} else {
			fmt.Println("Answer : " + ns + "=>")
			var ip string
			for _, ans := range r.Answer {
				anss := splitRR(ans)
				fmt.Printf("\t%s -> %s\n",
					dst,
					anss[4],
				)
				ip = anss[4]
			}
			return ip
		}
	}
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
			if debug {
				log.Printf("NS %v,Root %v\n", ns, root)
			}
			ns = recRsolve(ns, root, n+1)
			if debug {
				log.Printf("NS %v,Root %v\n", ns, root)
			}
		}
		r := rrsearch(ns, dst, dns.TypeA)
		if len(r.Answer) == 0 {
			rrs := splitRR(r.Ns[rand.Intn(len(r.Ns))])
			nss, typ := setNS(rrs, r, ns)

			for strings.Compare(typ, "AAAA") == 0 {
				rrs := splitRR(r.Ns[rand.Intn(len(r.Ns))])
				nss, typ = setNS(rrs, r, ns)
				if debug {
					log.Printf("Type %v\n", typ)
				}
			}
			fmt.Println(tab + ns + "=>")
			fmt.Printf(tab+"\t%s -> %s\n",
				rrs[0],
				rrs[4],
			)
			if strings.Compare(rrs[0], ".") == 0 {
				fmt.Println("Domain Name Not found")
				os.Exit(1)
			}

			ns = nss
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
	app := cli.NewApp()
	app.Usage = "It is a tool to see Iterative Search of the DNS is how to."
	app.Version = Version

	app.Commands = []cli.Command{
		{
			Name:    "rec",
			Aliases: []string{"r"},
			Usage:   "Iterative Search",
			Action: func(c *cli.Context) {
				if debug {
					log.SetFlags(log.Llongfile)
				}
				recRsolve(c.Args().First(), root, 0)
			},
		},
		{
			Name:    "norec",
			Aliases: []string{"n"},
			Usage:   "No Iterative Search",
			Action: func(c *cli.Context) {
				if debug {
					log.SetFlags(log.Llongfile)
				}
				noRecRsolve(c.Args().First(), root)
			},
		},
	}

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "root",
			Value:       "202.12.27.33",
			Usage:       "Root DNS Server's IP address",
			Destination: &root,
		},
		cli.BoolFlag{
			Name:        "debug",
			Usage:       "Debug Option for Developer",
			EnvVar:      "false",
			Destination: &debug,
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}
