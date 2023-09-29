# Running an RDC-supporting Firefox Nightly in the VM
If you import the [Virtual Machine image](https://drive.google.com/file/d/1N1M0dv8lLD3asQPw8uvkYyYtii5azMbn/view?usp=sharing) into your VirtualBox and run the RDC-supporting Firefox Nightly within the Virtual Machine, you can easily run followed by the simple commands.
```
cd /home/ydgcjh2019/mozilla-unified
./mach run
```
You can find the RDC-supporting functions in the directory /home/ydgcjh2019/mozilla-unified/security/nss/lib/ssl. After making changes to the code for testing, it's essential to recompile the code. Compiling the code within the Virtual Machine is a straightforward process—just use a single command:
```
./mach build.
```

# Building an RDC-supporting Firefox Nightly from the source codes

## Requirement
Before building a Firefox Nightly browser with RDC support, it is essential to install the required dependencies of Firefox Nightly. The simplest method to accomplish this is by building the vanilla version of Firefox Nightly. Therefore, please proceed with building Firefox Nightly and refer to [[link](https://firefox-source-docs.mozilla.org/setup/linux_build.html)] for further instructions on installing the dependencies.

You also need to install curl and rustc

curl
```
$ apt-get install libssl-dev
$ wget https://curl.se/download/curl-7.80.0.tar.gz
$ tar xvfz curl-7.80.0.tar.gz
$ cd curl-7.80.0/
$ ./configure --with-openssl --prefix=/<your home>/.mozbuild/sysroot-x86_64-linux-gnu/usr
$ make
$ make install
```
rustc
```
$ apt autoremove rustc
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ vi ~/.bashrc
# Add the follow command into your bashrd
export PATH=~/.cargo/bin:$PATH
$ source ~/.bashrc
$ rustup default 1.59.0
```

## Build
Remove a `mozilla-unified` directory that is created after building the vanilla Firefox Nightly browser.
```
$ rm -rf mozilla-unified
```
Download the RDC-supporting Firefox Nightly browser [[mozilla-unified.tar.xz](https://drive.google.com/file/d/1k74gSh-nYOXFPo5tycP6JgKATgElORvt/view?usp=sharing)]

Extract the tar file. It will take several minutes to complete.
```
$ tar -xf mozilla-unified.tar.xz
```
Now you see a new `mozilla-unified` directory, which is able to build the RDC-supporting Firefox Nightly browser.

Enter the `mozilla-unified` directory
```
$ cd mozilla-unified
```
Now you are ready to build the browser. It will take a long time ranging from several minutes to hours depending on your system resources.
```
$ ./mach clobber
$ ./mach build
```
If you success to build, you are able to launch the RDC-supporting browser.
```
$ ./mach run
```
## Source code note for further development

RDC-supporting functions are developed in the [ssl](https://github.com/revtls/revtls/tree/main/browser/ssl) directory of the NSS library and are divided into two main categories:
- RDC parsing and verification
- helper tools for using RDC

### RDC parsing and verification
For analysis of the RDC parsing and verification function, we recommend that you begin with the code in [tls13con.c](https://github.com/revtls/revtls/blob/main/browser/ssl/tls13con.c). Within this file, you'll find two main functions responsible for parsing and verifying the RDC.
- `static SECStatus tls13_ReadDDC(sslSocket *ss, SECItem *data, sslDDC *ddc)`
- `SECStatus tls13_HandleCertificateVerify(sslSocket *ss, PRUint8 *b, PRUint32 length)`

`tls13_ReadDDC` parses the key value of JSON-formatted RDC, and converts the base64-encoded RDC public key and signature to DER format so that they can be used in the existing NSS library verification procedure.

When the `tls13_HandleCertificateVerify` function encounters an RDC extension among other TLS extensions, it invokes the `tls13_VerifyDDC` function. Within `tls13_VerifyDDC`, The revocation status of the RDC is validated, and the RDC signature is verified. Once the operations in `tls13_VerifyDDC` are completed successfully, `tls13_HandleCertificateVerify` utilizes the RDC public key, instead of relying on the TLS certificate's public key, to verify the CertificateVerify signature.

### Helper tools for using RDC
Within [tls13ddc.c](https://github.com/revtls/revtls/blob/main/browser/ssl/tls13ddc.c), you'll find a collection of utility functions designed to facilitate the usage of RDC. These functions encompass tasks, including parsing and verifying RDC, such as the `tls13_VerifyDDC`