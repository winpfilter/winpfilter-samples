---
name: ipv4-dns-redirect
type: driver
description: "Redirect all DNS query to another DNS server. It allows user surfing the Internet even though they have bad DNS settings."
languages:
- c
---

# IPv4 DNS Query Redirector

The IPv4 DNS Query Redirector sample illustrates the usage of the winpfilter hook to modify packets.

To test the driver, install it on the target machine and it will take effect.

> [NOTICE]
> This sample provides an example of winpfilter module intended for education purposes. The driver is not intended for use in a production environment.
