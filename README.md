# mini-dns-resolver
Minimal DNS resolver written in C for a school project.

It doesn't do much beyond using A and CNAME records to resolve the IPv4 address of a domain name passed in as an argument, but it 
was a good exercise in implementing a (subset of) a protocol specification at a fairly low level.

## Building

Check out the project to somewhere that has both `gcc` and UNIX-style system networking libraries. From the root directory, run
`make`. That should be it.

## Usage

`./resolver <domain name> <DNS server>`

Common public DNS servers are `8.8.8.8`, `8.8.4.4` (Google) or `1.1.1.1` (Cloudflare)
