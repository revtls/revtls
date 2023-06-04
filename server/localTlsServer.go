package main

import (
	"certandrdcgen"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

func main() {

	rootTemplate, rootPrivateKey := certandrdcgen.CreateRootCertificate("rootCA")
	domainOwnerTemplate, domainOwnerPrivateKey := certandrdcgen.LocalCreateDomainOwnerCertificate("localhost", rootPrivateKey, *rootTemplate)
	certandrdcgen.LocalCreateDomainOwnerRDC(domainOwnerPrivateKey, *domainOwnerTemplate)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		fmt.Fprintf(w, "Hello TLS with doTLS!\n")
	})

	srv := &http.Server{
		Addr:    ":4000",
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			DDCKeyLocation:           "#do#key0",
		},
	}

	log.Printf("Starting server on %s", ":4000")

	// Fourth parameter is a flag, which is 0 for vanila TLS and 1 for doTLS
	err := srv.ListenAndServeTLS("localDomainOwnerCert.pem", "localDomainOwnerDDC.json", "localDomainOwnerDDCKey.pem", 1)
	// err := srv.ListenAndServeTLS("localDomainOwnerCert.pem", "", "localDomainOwnerKey.pem", 0)
	if err != nil {
		log.Fatal(err)
	}

}
