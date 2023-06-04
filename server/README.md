We offer two server applications: localTlsServer.go and tlsServer.go.

For testing in a local environment with a self-generated TLS certificate, you can utilize localTlsServer.go. When executing localTLSServer.go, it generates the self-generated TLS certificate and RDC and their corresponding key pair, and initiates the RDC-supported HTTPS web server.

Alternatively, if you prefer to test on the web using a TLS certificate obtained from a trusted Certificate Authority (CA), you can make use of tlsServer.go.

Before executing the server, you need to configure GOROOT using our [GOROOT](https://github.com/revtls/revtls/go)