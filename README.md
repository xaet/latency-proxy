<p align="center"> <em>a SOCKS5 + HTTP proxy with simulated network conditions, device fingerprinting and geo-aware upstream routing — my networking exam project</em> </p><p align="center"> <img alt="Go" src="https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=for-the-badge&logo=go"> <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge"> <img alt="Protocol" src="https://img.shields.io/badge/protocol-SOCKS5%20%2B%20HTTP-ff69b4?style=for-the-badge"> <img alt="Status" src="https://img.shields.io/badge/exam%20project-%E2%9C%94%20submitted-success?style=for-the-badge"> </p>

## so this is my networking / systems programming exam project, it's a proxy server written in Go that speaks both SOCKS5 (RFC 1928) and HTTP CONNECT (RFC 7231), and it does some genuinely neat things on top of plain proxying:
* simulates realistic network conditions (latency, jitter, packet loss, bandwidth caps)
* applies device fingerprint profiles (User-Agent, Accept-Language, TLS hints, custom headers)
* routes traffic through geo-aware upstream proxies using a GeoIP database
* exposes a live HTTP control API so you can tweak everything while it's running
* has a little interactive REPL if you just want to poke at it

#### i built it because i was reading about how VPNs and CDNs behave differently depending on where u appear to be connecting from, and i wanted to build a sandbox to actually see how that works. plus my networking professor said "make something with sockets" and, well. here we are
---
## what it actually does
* SOCKS5 server on TCP (full CONNECT / BIND / UDP ASSOCIATE support)
* HTTP proxy with CONNECT tunneling and plain-HTTP forwarding
* UDP relay with NAT-style session tracking (60s expiry, auto cleanup)
* Username/password auth (RFC 1929) when you want it
* IP allow / block lists using CIDR notation
* Device profiles — swap your User-Agent, Accept-Language, extra headers, TLS version and cipher suite hints per profile
* GeoIP routing — pick the upstream proxy whose location matches the target's country (MaxMind .mmdb)
* Upstream chaining — SOCKS5 or HTTP upstream proxies, optionally with auth
* Traffic shaping — latency, jitter, packet loss and bandwidth limits via golang.org/x/time/rate
* Connection tracking with live byte counters
* HTTP control API on port http_port + 1 (/status, /config, /connections, /set/*, /profiles, /upstreams)
* Graceful shutdown — drains connections on SIGINT / SIGTERM
* Interactive REPL — start, stop, set, jitter, loss, bandwidth, status, connections, config, profile list, upstream list, help
---
## installation
#### you'll need Go 1.21 or newer.
```
git clone https://github.com/xaet/latency-proxy.git
go mod init proxy
go get github.com/oschwald/geoip2-golang
go get golang.org/x/time/rate
```
#### build
```
go build
```
#### commands
```
start                        - start proxy
stop                         - stop proxy
set <ms>                     - set latency (ms)
jitter <ms>                  - set jitter (ms)
loss <percent>               - set packet loss (0-100)
bandwidth <bps>              - set bandwidth limit (bytes/s, 0 = unlimited)
status                       - show status
connections                  - list active connections
config                       - show full config
profile list                 - list device profiles
upstream list                - list upstream proxies
help                         - this help
exit/quit                    - exit
```
---
## license
#### MIT. do what u want, don't blame me if u point it at something u shouldn't.
