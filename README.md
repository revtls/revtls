# Revocable Delegated Credential (RDC)
We propose Revocable Delegated Credential (RDC), which provides a revocation method for DCs. Our implementation and evaluation focus on two main aspects (section 6.2 in the paper): 1) whether the HTTPS server can be operated using a TLS certificate, an RDC, and the RDC’s private key (without the TLS certificate’s private key), and 2) whether the domain owners can revoke the RDC using their DNS provider or their own authoritative DNS server.

We provide a [Virtual Machine image](https://drive.google.com/file/d/1N1M0dv8lLD3asQPw8uvkYyYtii5azMbn/view?usp=sharing) (using VirtualBox) that contains an RDC-supporting HTTPS server and an RDC-supporting browser. You can simply import the Virtual Machine image into your VirtualBox and use it to run the server and the browser. 

You can watch a [video demonstration](https://github.com/revtls/revtls/tree/main/video) of communication between the RDC-supporting HTTPS server and the RDC-supporting Firefox Nightly.

This repository also provides source codes of a [RDC-supporting HTTPS web server](https://github.com/revtls/revtls/tree/main/server) and [GOROOT](https://github.com/revtls/revtls/tree/main/go), along with the [RDC-enabled Firefox Nightly browser](https://github.com/revtls/revtls/tree/main/browser).

Detailed instruction is provided [here](https://docs.google.com/document/d/1LOoRr3A7wcy_3Puu2Y4ne-mTDDnqrtkQ/edit?usp=sharing&ouid=112950176885451216508&rtpof=true&sd=true)
