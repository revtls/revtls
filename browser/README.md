## Building Firefox Nightly with doTLS implementation

### Requirement
Before building a Firefox Nightly browser with RDC support, it is essential to install the required dependencies of Firefox Nightly. The simplest method to accomplish this is by building the vanilla version of Firefox Nightly. Therefore, please proceed with building Firefox Nightly and refer to [[link](https://firefox-source-docs.mozilla.org/setup/linux_build.html)] for further instructions on installing the dependencies.

You also need to install curl and rustc

curl
```
# wget https://curl.se/download/curl-7.80.0.tar.gz
# tar xvfz curl-7.80.0.tar.gz
# cd curl-7.80.0/
# ./configure --with-openssl --prefix=/home/chahn/.mozbuild/sysroot-x86_64-linux-gnu/usr
# make
# make install
```
rustc
```
#apt autoremove rustc
#curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
#export PATH=~/.cargo/bin:$PATH
#rustup default 1.59.0
```

### Build
Remove a `mozilla-unified` directory that is created after building the vanilla Firefox Nightly browser.
```
# rm -rf mozilla-unified
```
Download the RDC-supporting Firefox Nightly browser [[mozilla-unified.tar.xz](https://drive.google.com/file/d/1k74gSh-nYOXFPo5tycP6JgKATgElORvt/view?usp=sharing)]

Extract the tar file. It will take several minutes to complete.
```
# tar -xf mozilla-unified.tar.xz
```
Now you see a new `mozilla-unified` directory, which is able to build the RDC-supporting Firefox Nightly browser.

Enter the `mozilla-unified` directory
```
# cd mozilla-unified
```
Now you are ready to build the browser. It will take a long time ranging from several minutes to hours depending on your system resources.
```
# ./mach clobber
# ./mach build
```
If you success to build, you are able to launch the RDC-supporting browser.
```
# ./mach run
```
When accessing the HTTPS server initiated through `localTlsServer.go`, it is necessary to import the certificate of the self-generated root CA into your browser.