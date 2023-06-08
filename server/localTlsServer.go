package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

func main() {

	//rootTemplate, rootPrivateKey := certandrdcgen.CreateRootCertificate("rootCA")
	//domainOwnerTemplate, domainOwnerPrivateKey := certandrdcgen.LocalCreateDomainOwnerCertificate("localhost", rootPrivateKey, *rootTemplate)
	//domainOwnerTemplate, domainOwnerPrivateKey := certandrdcgen.LocalCreateDomainOwnerCertificate("sspki.com", rootPrivateKey, *rootTemplate)
	//certandrdcgen.LocalCreateDomainOwnerRDC(domainOwnerPrivateKey, *domainOwnerTemplate)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		fmt.Fprintf(w, "Hello TLS with RDC\n")
	})

	srv := &http.Server{
		//Addr:    ":4000",
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			DDCKeyLocation:           "#do#key0",
		},
	}

	log.Printf("Starting server on %s", ":443")

	// Fourth parameter is a flag, which is 0 for vanila TLS and 1 for RDC-supporting TLS
	err := srv.ListenAndServeTLS("localDomainOwnerCert.pem", "localDomainOwnerRDC.json", "localDomainOwnerRDCKey.pem", 1)
	// err := srv.ListenAndServeTLS("localDomainOwnerCert.pem", "", "localDomainOwnerKey.pem", 0)
	if err != nil {
		log.Fatal(err)
	}

}
