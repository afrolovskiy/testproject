package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/domainr/whois"
	"github.com/emicklei/go-restful"
	"github.com/miekg/dns"
)

func unknownTypeHandler(req *restful.Request, resp *restful.Response) {
	resp.WriteErrorString(http.StatusBadRequest, "unknown check type")
}

func whoisHandler(req *restful.Request, resp *restful.Response) {
	domain := req.PathParameter("domain")
	info, err := whois.Whois(strings.ToLower(domain))
	if err != nil {
		io.WriteString(resp, "")
	}
	io.WriteString(resp, info)
}

func mxHandler(req *restful.Request, resp *restful.Response) {
	var mxs []string
	domain := req.PathParameter("domain")

	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	msg.RecursionDesired = true

	for _, server := range config.Servers {
		r, _, _ := client.Exchange(msg, server+":"+config.Port)
		if r != nil && r.Rcode == dns.RcodeSuccess {
			for _, a := range r.Answer {
				if mx, ok := a.(*dns.MX); ok {
					mxs = append(mxs, strings.ToLower(mx.Mx))
				}
			}
			break
		}
	}

	rdata, err := json.Marshal(mxs)
	if err != nil {
		io.WriteString(resp, "[]")
	} else {
		io.WriteString(resp, string(rdata))
	}
}

var handlers = map[string]interface{}{
	"whois": whoisHandler,
	"mx":    mxHandler,
}

func check(req *restful.Request, resp *restful.Response) {
	ctype := req.PathParameter("type")
	if handler, ok := handlers[ctype]; ok {
		handler.(func(*restful.Request, *restful.Response))(req, resp)
	} else {
		unknownTypeHandler(req, resp)
	}
}

func main() {
	ws := new(restful.WebService)
	ws.Route(ws.GET("/check/{domain}/{type}").To(check).
		Param(ws.PathParameter("domain", "domain name").DataType("string")).
		Param(ws.PathParameter("type", "check type").DataType("string")))
	restful.Add(ws)

	log.Printf("start listening on localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
