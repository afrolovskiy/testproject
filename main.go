package main

import (
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/domainr/whois"
	"github.com/emicklei/go-restful"
)

func main() {
	ws := new(restful.WebService)
	ws.Route(ws.GET("/check/{domain}").To(check).
		Param(ws.PathParameter("domain", "domain name").DataType("string")))
	restful.Add(ws)

	log.Printf("start listening on localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func check(req *restful.Request, resp *restful.Response) {
	domain := req.PathParameter("domain")
	info, err := whois.Whois(strings.ToLower(domain))
	if err != nil {
		io.WriteString(resp, "")
	}
	io.WriteString(resp, info)
}
