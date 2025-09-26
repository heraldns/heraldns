# HeralDNS

**Announce your containers to the world.**

HeralDNS automatically registers Docker containers in DNS, making them discoverable on your network. Built for the IPv6-first future where every container can have a globally routable address.

[![Docker Pulls](https://img.shields.io/docker/pulls/heraldns/sync)](https://hub.docker.com/r/heraldns/sync)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## The Problem

You're running Docker containers with IPv6 addresses that should be globally routable. Your ISP might change your IPv6 prefix. You want:

- Containers automatically registered in DNS when they start
- DNS records updated when IP addresses change (dynamic prefixes)
- Both IPv4 and IPv6 support (A and AAAA records)
- Secure updates to your DNS server
- Fine-grained control over which containers get registered

Traditional solutions like manual DNS entries break with dynamic prefixes. NAT "solves" this for IPv4 but defeats the purpose of IPv6's global routability. Container-native DNS solutions don't integrate with your existing DNS infrastructure.

**HeralDNS solves this.** It watches your containers, detects IP changes, and keeps your DNS server in sync—automatically.

## Features

- 🌍 **IPv6-First**: Built for globally routable IPv6, handles dynamic prefix changes gracefully
- 🔐 **Secure Authentication**: GSS-TSIG (Kerberos) for Active Directory DNS, TSIG keys for BIND/PowerDNS
- 🏷️ **Label-Based Control**: Fine-grained per-container configuration using Docker labels
- 🔄 **Automatic Sync**: Detects IP changes and updates DNS in real-time
- 🌐 **Multi-DNS Support**: Works with Active Directory, BIND, PowerDNS, and more
- 🎯 **Network Filtering**: Only register IPs from specific Docker networks
- 🧹 **Auto Cleanup**: Removes DNS records when containers stop
- ⚙️ **Flexible Configuration**: Global defaults with per-container overrides

## Quick Start

### Active Directory DNS (GSS-TSIG)

```yaml
version: '3.8'

services:
  heraldns:
    image: heraldns/sync:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      DNS_PROVIDER: "gss-tsig"
      DNS_SERVER: "dc01.example.com"
      DNS_ZONE: "example.com"
      KRB_PRINCIPAL: "svc-dns@EXAMPLE.COM"
      KRB_PASSWORD: "password"
      DEFAULT_NETWORK: "public"
      DEFAULT_IP_VERSION: "both"

  # Your container - automatically registered!
  webapp:
    image: nginx
    labels:
      dns.hostname: "www.example.com"
    networks:
      - public

networks:
  public:
    enable_ipv6: true
```

### BIND/PowerDNS (TSIG Keys)

```yaml
services:
  heraldns:
    image: heraldns/sync:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      DNS_PROVIDER: "tsig"
      DNS_SERVER: "ns1.example.com"
      DNS_ZONE: "example.com"
      TSIG_KEY_NAME: "update-key"
      TSIG_KEY_SECRET: "base64secret=="
      TSIG_ALGORITHM: "hmac-sha256"
```

## How It Works

1. **Watch**: HeralDNS monitors Docker events for container starts/stops and network changes
2. **Discover**: Extracts hostnames from labels and IP addresses from container networks
3. **Filter**: Only processes containers and networks you specify
4. **Update**: Securely updates your DNS server using RFC 2136 dynamic updates
5. **Clean**: Removes DNS records when containers stop

```
Container starts → HeralDNS detects → Updates DNS → www.example.com resolves!
ISP changes IPv6 prefix → Docker assigns new IP → HeralDNS updates DNS → Still works!
Container stops → HeralDNS removes DNS record → Clean!
```

## Core Concepts

### Registration Modes

**Explicit (default):** Only register containers with `dns.hostname` label
```yaml
services:
  myapp:
    labels:
      dns.hostname: "app.example.com"
```

**Automatic:** Register all containers using their names
```yaml
environment:
  REGISTER_ALL: "true"

services:
  web01:
    # Registers as web01.example.com
    
  redis:
    labels:
      dns.ignore: "true"  # Explicitly excluded
```

### Network Filtering

Prevent registering internal Docker IPs:

```yaml
environment:
  DEFAULT_NETWORK: "public"  # Only check this network

services:
  app:
    networks:
      - public   # IP from here gets registered
      - internal # IP from here ignored
```

Per-container override:
```yaml
services:
  app:
    labels:
      dns.network: "dmz"  # Use this network instead
```

### IP Version Control

```yaml
# Global default
environment:
  DEFAULT_IP_VERSION: "both"  # ipv4, ipv6, or both

# Per-container override
services:
  modern-app:
    labels:
      dns.ip_version: "ipv6"  # IPv6 only
```

## Configuration

### DNS Providers

#### GSS-TSIG (Active Directory)

```yaml
environment:
  DNS_PROVIDER: "gss-tsig"
  DNS_SERVER: "dc01.example.com"  # FQDN or IP
  DNS_ZONE: "example.com"
  KRB_PRINCIPAL: "svc-dns@EXAMPLE.COM"
  
  # Choose one authentication method:
  KRB_PASSWORD: "password"                    # Option 1: Password
  KRB_KEYTAB_BASE64: "base64encodedkeytab"   # Option 2: Base64 keytab
  # Or mount keytab at /keytab                # Option 3: Volume mount
```

#### TSIG (BIND, PowerDNS, etc.)

```yaml
environment:
  DNS_PROVIDER: "tsig"
  DNS_SERVER: "ns1.example.com"
  DNS_ZONE: "example.com"
  TSIG_KEY_NAME: "update-key"
  TSIG_KEY_SECRET: "base64secret=="
  TSIG_ALGORITHM: "hmac-sha256"  # hmac-sha256, hmac-sha512, etc.
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_PROVIDER` | Yes | - | `gss-tsig` or `tsig` |
| `DNS_SERVER` | Yes | - | DNS server FQDN or IP |
| `DNS_ZONE` | Yes | - | DNS zone to update |
| `REGISTER_ALL` | No | `false` | Register all containers by default |
| `DEFAULT_NETWORK` | No | (all) | Comma-separated network names |
| `DEFAULT_IP_VERSION` | No | `both` | `ipv4`, `ipv6`, or `both` |
| `DNS_TTL` | No | `300` | TTL in seconds |
| `POLL_INTERVAL` | No | `60` | Check interval in seconds |

### Container Labels

| Label | Description |
|-------|-------------|
| `dns.hostname` | Hostname to register (required unless `REGISTER_ALL=true`) |
| `dns.ignore` | Set to `true` to skip registration |
| `dns.network` | Network(s) to use for IP addresses |
| `dns.ip_version` | `ipv4`, `ipv6`, or `both` |

## Use Cases

### 1. IPv6-First Home Lab

You have globally routable IPv6 but your ISP uses dynamic prefixes:

```yaml
environment:
  DNS_PROVIDER: "tsig"
  DNS_SERVER: "192.168.1.1"  # Your router running BIND
  DNS_ZONE: "home.lab"
  DEFAULT_IP_VERSION: "ipv6"
  DEFAULT_NETWORK: "public_v6"

networks:
  public_v6:
    enable_ipv6: true
    ipam:
      config:
        - subnet: "2001:db8::/64"  # Prefix changes? No problem!
```

### 2. Dual-Stack Public Services

Run services accessible via both IPv4 and IPv6:

```yaml
environment:
  DEFAULT_IP_VERSION: "both"
  DEFAULT_NETWORK: "dmz"

services:
  web:
    labels:
      dns.hostname: "www.example.com"
    # Gets both A and AAAA records
```

### 3. Development Environment with Active Directory

Auto-register dev containers in corporate AD DNS:

```yaml
environment:
  DNS_PROVIDER: "gss-tsig"
  DNS_SERVER: "dc.corp.internal"
  DNS_ZONE: "dev.corp.internal"
  REGISTER_ALL: "true"
  DEFAULT_NETWORK: "dev_network"

services:
  api-v2:
    # Automatically registers as api-v2.dev.corp.internal
```

### 4. Multi-Network Containers

Container on multiple networks, only expose one:

```yaml
services:
  app:
    labels:
      dns.hostname: "app.example.com"
      dns.network: "public"  # Only register this network's IP
    networks:
      - public
      - backend
      - cache
```

## Why HeralDNS?

### The IPv6 Reality

IPv6 gives every container a globally routable address—no NAT needed. But dynamic prefixes from ISPs break static DNS. HeralDNS embraces this reality:

- Automatically updates DNS when prefixes change
- No manual intervention required
- Works with standard DNS infrastructure
- Respects IPv6's end-to-end principle

### Comparison to Alternatives

| Solution | IPv6 Dynamic Prefixes | Existing DNS Integration | Secure Updates | Per-Container Control |
|----------|----------------------|-------------------------|----------------|----------------------|
| **HeralDNS** | ✅ | ✅ | ✅ | ✅ |
| Manual DNS entries | ❌ | ✅ | ✅ | ✅ |
| Container DNS servers | ✅ | ❌ | N/A | ✅ |
| DynDNS services | ⚠️ (whole host) | ⚠️ | ⚠️ | ❌ |
| Traefik/proxy DNS | ✅ | ❌ | N/A | ✅ |

## Advanced Usage

### Multiple DNS Servers (Coming Soon)

```yaml
environment:
  DNS_SERVERS: "ns1.example.com,ns2.example.com"
```

### Custom DNS Providers (Coming Soon)

Support for Cloudflare API, Route53, etc.

### Event-Driven Updates (Coming Soon)

React to Docker events in real-time instead of polling.

## Troubleshooting

### Containers Not Registering

Check that containers meet requirements:
- Have `dns.hostname` label (or `REGISTER_ALL=true`)
- Don't have `dns.ignore=true`
- Have IP on specified network
- Check logs: `docker logs heraldns`

### Wrong IP Registered

Specify the network explicitly:
```yaml
labels:
  dns.network: "correct_network"
```

### IPv6 Not Working

Ensure network has IPv6 enabled:
```yaml
networks:
  mynet:
    enable_ipv6: true
    ipam:
      config:
        - subnet: "2001:db8:1::/64"
```

### GSS-TSIG Authentication Fails

Verify service account has DNS update permissions in AD:
```powershell
Add-DnsServerResourceRecordPermission -ZoneName "example.com" `
  -Name "." -Type "A" -User "svc-dns" -Action "Allow"
```

## Contributing

We welcome contributions! HeralDNS is designed to support multiple DNS providers and use cases.

**Roadmap:**
- [ ] Additional DNS providers (Cloudflare, Route53, Azure DNS)
- [ ] Event-driven updates (no polling)
- [ ] Webhook notifications
- [ ] Prometheus metrics
- [ ] Multi-architecture Docker images

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

Built with:
- [dnspython](https://github.com/rthalley/dnspython) - DNS library with GSS-TSIG support
- [python-gssapi](https://github.com/pythongssapi/python-gssapi) - Kerberos authentication
- [docker-py](https://github.com/docker/docker-py) - Docker API client

Inspired by the need for IPv6-first container networking without sacrificing DNS integration.

---

**HeralDNS** - Announce your containers to the world.
