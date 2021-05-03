# DNS Spew

This is a simple tool called dns-spew that uses the high-speed parallel framework in libvdns (a library from the [Vantages DNS library](https://gitlab.com/ginipginob/vantages) 
open source project) to issue DNS queries for A records, to any DNS domain names that you choose. 
The tool will log all of the responses, even when more than one response is received.

# Table of Contents

* [Compiling](#compiling)
* [Dependencies](#dependencies)
* [Example Output](#example)


#<a name="compiling"></a>
Compiling jacksniff
===========

```
make
```

#<a name="dependencies"></a>
Dependencies
======

To compile jacksniff, there are a couple of dependencies: libpcap, and libvdns.
The first, libpcap, can be installed in numerous ways (described below).  The second,
libvdns, is part of the open source [Vantages DNS library](https://gitlab.com/ginipginob/vantages).

## Vantages (libvdns)
To install Vantages, follow its directions **but** you only need its DNS library.  To expedite installation and minimize other
dependencies, you can configure it with:

```
./configure --without-vantaged
make
sudo make install
```

