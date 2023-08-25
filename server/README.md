Before executing the server, you need to configure the GOROOT environment variable using our [GOROOT](https://github.com/revtls/revtls/tree/main/go).

```
$ vi ~/.bashrc
//Add the following commands to your bashrc
export GOPATH=<your GOPATH path>
export GOROOT=<your GOROOT path>
export PATH=$PATH:<your GOROOT path>/bin
// Save and close the bashrc

// Apply the newly added environment variables
$ source ~/.bashrc
```
You also need to locate your TLS certificate and its private key here
```
$ cp <your TLS certificate location> ./
$ cp <your TLS certificate's private key location> ./

//NOTE: If the names of your TLS certificate and its corresponding private key differ from cert.pem and privatekey.pem, please rename them accordingly.
```

You are now able to run the RDC-supporting HTTPS server using tlsServer.go. tlsServer.go creates an RDC and its private key using privkey.pem (TLS certificate's private key), and it uses cert.pem (TLS certificate), domainOwnerDDC.json (RDC), and domainOwnerDDCKey.pem (RDC’s private key) to launch the RDC-supporting HTTPS server (see 66 line in the tlsServer.go).

```
$ go run tlsServer.go

//If you encounter an error saying "package certandrdcgen is not in GOROOT', try 'go env -w GO111MODULE=off'
```