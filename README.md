# About #

mdnssd-min is a minimal client for mDNS and DNS-SD that is designed to do only the following:

  1. Use DNS-SD over mDNS to search for a specified service type on one interface.

  2. Use mDNS to resolve the IP addresses for all results returned by the DNS-SD query.

When run, it returns the hostname, IP and port for each instance of a service of a specified type running on connected LANs.

# Features #

* Requires no libraries (other than a libc of some kind)
* Small size: 18 KB (without debugging symbols on x86)
* Simple operation
* Helpful debug mode

# Usage #

```
Given a service type, return a set of hostnames, IPs and port numbers 
for instances of services of the given type.

Usage: ./mdnssd-min [-a <answers>] [-t <time>] <_service._type.local>

  answers: Minimum number of answers wanted (default: 1) [optional]
  time: Maximum number of seconds to wait for answers (default: 3) [optional]
  -d: Enable very verbose debug output [optional]
```
mdnssd-min will wait until it has either received the minimum number of answers, or the time expires. E.g. in default operation it will wait until it receives one answer or three seconds have passed.

## Example usage ##

If run with e.g:

```
./mdnssd-min -a 3 -t 10 _nodeconf._tcp.local
```

If two node configuration servers reply within the ten-second time-frame, then e.g. the following will be printed to stdout:

```
anodeserver.local         10.0.0.10   2000
anothernodeserver.local   10.0.0.42   3000
```

Where the format is:

```
<hostname>\t<ip>\t<port>\n
```

If no answers are received in the given time-frame, then nothing is output.

Return value is always 0 unless an error is encountered.

# RFC compliance #

There are some things that this program should do, according to RFC 6762 and 6763, that it does not do, such as, but not limited to:

* It does not care about TTL at all, so:
** No expiration of cached results.
** No re-sending of a query after TTL expiration.
* It completely ignores negative responses.
* It never sends any Known-Answer records.
* It only works with multicast queries and responses.
* It only supports IPv4

This program is meant to be run once, send out a single DNS-SD query, listen for responses for a few seconds, resolve the hostname of any returned results to IPv4 addresses and print the resulting information to stdout.

This program was designed to be used in the sudo mesh firmware (based on OpenWRT) for use in peoplesopen.net

# Planned improvements #

* Support waiting for a certain minimum number of results to arrive.
* Add IPv6 support
* Implement continuous operation support.
** Cache queries until TTL experies. 
** Check for and fix potential memory leaks.
* Add TXT record support.
* Implement unicast reply support.

# Alternatives available for OpenWRT #

## mdns-utils ##

These are example applications developed by Apple and are extremely limited.

We encountered problems working with these tools from lua without requiring more than lua's built-in popen and execute calls. 

## bind-dig ##

This only works for mDNS, not for DNS-SD, and requires bind-libs which has an ipk size of 768 kB.

## Use avahi-utils:
    This depends on dbus, libdbus, libavahi and avahi-daemon, which together 
    take up over 500 kB as ipks.


Note: The priority and weight fields of SRV records are not reported.

# Testing, stability and security #

This software has only been tested against [Avahi](http://avahi.org/). It is possible and even likely that there are other DNS-SD and mDNS implementations out there that cause this software to fail spectacularly, or that maliciously crafted packets could be used to gain access to system running this program. Use at your own risk.

If you find any issues, please report them using the github issue tracker or to the author directly.

# License #

This software is licensed under GPLv3.