package main

import (
	"certandrdcgen"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func main() {

	domainOwnerCertPem, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}

	domainOwnerCertDer, _ := pem.Decode(domainOwnerCertPem)
	if domainOwnerCertDer == nil {
		log.Fatal("DER Decode err")
	}

	domainOwnerCert, err := x509.ParseCertificate(domainOwnerCertDer.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	domainOwnerPrivateKey, err := os.ReadFile("privkey.pem")
	if err != nil {
		log.Fatal(err)
	}

	certandrdcgen.CreateDomainOwnerRDC(domainOwnerPrivateKey, *domainOwnerCert)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		buf, err := ioutil.ReadFile("sendimg.png")
		if err != nil {
			log.Fatal(err)
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(buf)
	})

	//addr := flag.String("addr", ":443", "HTTPS network address")
	addr := flag.String("addr", ":4000", "HTTPS network address")
	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			DDCKeyLocation:           "#do#key0",
		},
	}

	log.Printf("Starting server on %s", ":443")
	err1 := srv.ListenAndServeTLS("cert.pem", "domainOwnerDDC.json", "domainOwnerDDCKey.pem", 1)
	if err1 != nil {
		log.Fatal(err1)
	}
}
