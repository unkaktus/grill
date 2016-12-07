grill
=====

`grill`, a-la global rate-limiting in Linux, is a scanner for
CVE-2016-5696 (aka pure TCP off-path).

Install
-------
```
$ go get github.com/nogoegst/grill
```

Kernel interference
-------------------
To avoid kernel interference during scan add a rule to your firewall to drop outgoing RST packets.

For PF (`/etc/pf.conf`):
```
block drop out quick proto tcp flags R/R
```
then `# pfctl -f /etc/pf.conf`.

For NetFilter:
```
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

```

Usage
-----
`grill` reads `stdin` and scans hosts from it (up to 16 concurrent scans). The input format is `host port\n`.

```
# cat probe | grill -i [interface] -sll [your MAC] -dll [gateway MAC] -sip [your IP] > results 
```

The output format is `host:port,recievedChACKs,sendingTime`.

So it goes. Have fun and make love.


Scanning the Tor network
------------------------
To scan relays of the Tor network, just fetch and format last consensus:
```
curl https://collector.torproject.org/recent/relay-descriptors/consensuses/`date -u +'%Y-%m-%d-%H-00-00-consensus'` | grep '^r '| awk '{print $7" "$8}' > probe-consensus
```

And then just pass resulted file to `grill` input.


Acknolegments
-------------
`grill` is hugely inspired by similar Scapy scanner by David Stainton [https://github.com/david415/scan_for_rfc5961]
and PoC by violentshell [https://github.com/violentshell/rover].
