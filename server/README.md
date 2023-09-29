## Running the RDC-supporting HTTPS server

### Set up GOROOT and GOPATH environment variables
```
# Root permission is required to run the HTTPS server on port 443.
Your_server:~$ sudo -i

# Set up GOROOT and GOPATH environment variables
Your_server(root):~$ vi ~/.bashrc
# Add the following commands to your bashrc
export GOPATH=<Path where the revtls is cloned>/revtls
export GOROOT=<Path where the revtls is cloned>/revtls/go
export PATH=$PATH:$GOROOT/bin
# Save and close the bashrc

# Apply the newly added environment variables
Your_server(root):~$ source ~/.bashrc

# Disabling GO111MODULE to enable the GOPATH environment
Your_server(root):~$ go env -w GO111MODULE=off
```

### Copy your TLS certificate and its private key to the GOPATH

```
$ cp <your TLS certificate location> $GOPATH/cert.pem
$ cp <your TLS certificate's private key location> $GOPATH/privkey.pem
```

### Execute the tlsServer.go to run the RDC-supporting HTTPS server
You are now able to run the RDC-supporting HTTPS server using tlsServer.go. tlsServer.go creates an RDC and its private key using privkey.pem (TLS certificate's private key), and it uses cert.pem (TLS certificate), domainOwnerDDC.json (RDC), and domainOwnerDDCKey.pem (RDC’s private key) to launch the RDC-supporting HTTPS server (see 66 line in the tlsServer.go).

```
$ go run tlsServer.go
```