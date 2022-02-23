# Introduction

`onion_peel` is a Rust library that makes it easier to build [pluggable transports](https://trac.torproject.org/projects/tor/wiki/doc/PluggableTransports) for tor (or any other application that speaks TCP and supports the [pluggable transport specification version 1](https://gitweb.torproject.org/torspec.git/tree/pt-spec.txt)) implemented by this library.

The API of this library is heavily inspired by [pyptlib](https://git.torproject.org/pluggable-transports/pyptlib.git).

## WARNING

*This is experimental code. Do not rely on it for security, and expect it to blow up. You have been warned.*

## Usage

### What onion_peel expects from your application

* It assumes that your application is executed by Tor as a managed proxy
* It assumes that your application acts as a proxy: it listens for traffic on a TCP port and pushes the traffic somewhere else
* It assumes that your application hosts a SOCKS4/5 server when it acts as a client for the tor client to connect through.

### Data flow

Quoting section 2 of the pluggable transports specification:

```plaintext
     +------------+                    +---------------------------+
     | Client App +-- Local Loopback --+ PT Client (SOCKS Proxy)   +--+
     +------------+                    +---------------------------+  |
                                                                      |
                 Public Internet (Obfuscated/Transformed traffic) ==> |
                                                                      |
     +------------+                    +---------------------------+  |
     | Server App +-- Local Loopback --+ PT Server (Reverse Proxy) +--+
     +------------+                    +---------------------------+

   On the client's host, the PT Client software exposes a SOCKS proxy
   [RFC1928] to the client application, and obfuscates or otherwise
   transforms traffic before forwarding it to the server's host.

   On the server's host, the PT Server software exposes a reverse proxy
   that accepts connections from PT Clients, and handles reversing the
   obfuscation/transformation applied to traffic, before forwarding it
   to the actual server software.  An optional lightweight protocol
   exists to facilitate communicating connection meta-data that would
   otherwise be lost such as the source IP address and port
   [EXTORPORT].

    [...]

   Each invocation of a PT MUST be either a client OR a server.

   All PT client forward proxies MUST support either SOCKS 4 or SOCKS 5,
   and SHOULD prefer SOCKS 5 over SOCKS 4.
```

### Examples

Refer to `examples/simple_forward.rs` to see how to implement a simple pluggable transport client and server that just forwards traffic without modification.

### TODO

* [ ] Error handling
* [ ] Examples
  * [X] Simple traffic forwarder (no obfuscation)
  * [X] Simple obfuscator
* [ ] Rustdocs
* [ ] Improved README
* [ ] Tests
  * [ ] ExtORPort wrong server HMAC
  * [ ] Unreachable (ext)ORPort
  * [ ] Missing (ext)ORPort env var
  * [ ] Unreadable extORPort cookie
  * [ ] Invalid extORPort cookie
  * [ ] End-to-end tests using the examples and real tor binaries
* [X] Extended ORPort protocol
* [ ] TransportControlPort protocol
* [ ] Support for reading client secrets from SOCKS auth
* [X] Support running in managed mode
* [ ] Support running in freestanding mode
