package main

import (
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/domainr/whois"
	"github.com/emicklei/go-restful"
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

var handlers = map[string]interface{}{
	"whois": whoisHandler,
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
