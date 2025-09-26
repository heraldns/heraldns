# HeralDNS

**Announce your containers to the world.**

HeralDNS automatically registers Docker containers in DNS, making them discoverable on your network. Built for the IPv6-first future where every container can have a globally routable address.

[![Docker Pulls](https://img.shields.io/docker/pulls/heraldns/sync)](https://hub.docker.com/r/heraldns/sync)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## The Problem

You're running Docker containers with IPv6 addresses that are globally routable. However, Watchtower updates your container, and its IP address changes. Or your ISP changes your prefix, breaking your static assignments. You want:

- Containers automatically registered in DNS when they start
- DNS records updated when IP addresses change (dynamic addresses)
- Both IPv4 and IPv6 support (A and AAAA records)
- Secure updates to your DNS server
- Fine-grained control over which containers get registered

Traditional solutions like manual DNS entries break when addresses or prefixes change. NAT "solves" this but defeats the purpose of IPv6's global routability. Container-native DNS solutions don't integrate with your existing DNS infrastructure.

**HeralDNS solves this.** It watches your containers, detects IP changes, and keeps your DNS server in sync—automatically.

## Features

- 🌍 **IPv6-First**: Built for globally routable IPv6, handles dynamic addresses gracefully
- 🔐 **Secure Authentication**: GSS-TSIG (Kerberos) for Active Directory, TSIG keys for BIND/PowerDNS
- 🏷️ **Label-Based Control**: Fine-grained per-container configuration using Docker labels
- 🔄 **Automatic Sync**: Detects IP changes and updates DNS in real-time
- 🌐 **Multi-Provider Support**: Works with Active Directory, BIND, PowerDNS, and more
- 📝 **Flexible Record Types**: A, AAAA, CNAME records with extensible architecture
- 🎯 **Network Filtering**: Only register IPs from specific Docker networks
- 🗂️ **Multi-Zone Support**: Update multiple DNS zones from a single deployment
- 🧹 **Auto Cleanup**: Removes DNS records when containers stop
- ⚙️ **Flexible Configuration**: Global defaults with per-container and per-record-type overrides

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
      DNS_ZONES: "example.com"
      KRB_PRINCIPAL: "svc-dns@EXAMPLE.COM"
      KRB_PASSWORD: "password"
      DEFAULT_NETWORK: "public"

  # Your container - automatically registered!
  webapp:
    image: nginx
    labels:
      dns.enable: "true"
      dns.fqdn: "www.example.com"
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
      DNS_ZONES: "example.com,internal.local"
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

### Label-Based Record Creation

HeralDNS uses a flexible label system: `dns.<type>.<attribute>`

**Without type (creates both A and AAAA):**
```yaml
services:
  webapp:
    labels:
      dns.enable: "true"
      dns.fqdn: "api.example.com"
      # Creates both A and AAAA records
```

**Type-specific records:**
```yaml
services:
  ipv6only:
    labels:
      dns.enable: "true"
      dns.aaaa.fqdn: "modern.example.com"
      # Creates only AAAA record
  
  ipv4only:
    labels:
      dns.enable: "true"
      dns.a.fqdn: "legacy.example.com"
      # Creates only A record
```

**CNAME records (point to primary FQDN):**
```yaml
services:
  webapp:
    labels:
      dns.enable: "true"
      dns.fqdn: "api.example.com"  # Primary A/AAAA
      dns.cname.hostname: "www,app"  # www and app → api.example.com
```

### Hostname vs FQDN

Labels support flexible splitting of FQDNs:

```yaml
# All three are equivalent:

# Option 1: Full FQDN
dns.fqdn: "api.staging.example.com"

# Option 2: Traditional hostname.domain
dns.hostname: "api"
dns.domain: "staging.example.com"

# Option 3: Record name in zone
dns.hostname: "api.staging"  # Can contain dots!
dns.domain: "example.com"
```

All create record `api.staging` in zone `example.com`.

### Multi-Zone Support

Update multiple zones simultaneously:

```yaml
environment:
  DNS_ZONES: "example.com,internal.local"

services:
  webapp:
    labels:
      dns.enable: "true"
      dns.hostname: "api"  # No domain specified
      # Creates: api.example.com AND api.internal.local
```

Or specify explicit zone:
```yaml
services:
  webapp:
    labels:
      dns.enable: "true"
      dns.hostname: "api"
      dns.domain: "example.com"  # Only this zone
```

## Configuration

### DNS Providers

#### GSS-TSIG (Active Directory)

```yaml
environment:
  DNS_PROVIDER: "gss-tsig"
  DNS_SERVER: "dc01.example.com"  # FQDN or IP
  DNS_ZONES: "example.com,corp.internal"
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
  DNS_ZONES: "example.com"
  TSIG_KEY_NAME: "update-key"
  TSIG_KEY_SECRET: "base64secret=="
  TSIG_ALGORITHM: "hmac-sha256"  # hmac-sha256, hmac-sha512, etc.
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_PROVIDER` | Yes | - | `gss-tsig` or `tsig` |
| `DNS_SERVER` | Yes | - | DNS server FQDN or IP |
| `DNS_ZONES` | Yes | - | Comma-separated zones (e.g., `example.com,internal.local`) |
| `REGISTER_ALL` | No | `false` | Register all containers by default |
| `EXPLICIT_SUBDOMAINS` | No | `false` | Require exact zone match (true) vs allow subdomains (false) |
| `DEFAULT_NETWORK` | No | (all) | Comma-separated network names |
| `DNS_TTL` | No | `300` | Default TTL in seconds |
| `POLL_INTERVAL` | No | `60` | Check interval in seconds |

### Container Labels

#### Control Labels

| Label | Description |
|-------|-------------|
| `dns.enable` | Set to `"true"` to register (required unless `REGISTER_ALL=true`) |
| `dns.ignore` | Set to `"true"` to skip registration |

#### Record Labels (Without Type = Both A and AAAA)

| Label | Description |
|-------|-------------|
| `dns.fqdn` | Full FQDN (e.g., `api.example.com`) |
| `dns.hostname` | Hostname or record name (can contain dots) |
| `dns.domain` | Domain or zone name |
| `dns.network` | Network(s) to use for IP addresses |
| `dns.ttl` | TTL for records |

#### Type-Specific Records

| Label | Description |
|-------|-------------|
| `dns.a.fqdn` / `dns.a.hostname` / `dns.a.domain` | A record only (IPv4) |
| `dns.aaaa.fqdn` / `dns.aaaa.hostname` / `dns.aaaa.domain` | AAAA record only (IPv6) |
| `dns.<type>.network` | Network for this record type |
| `dns.<type>.ttl` | TTL for this record type |

#### CNAME Records

| Label | Description |
|-------|-------------|
| `dns.cname.hostname` | Comma-separated hostnames (points to primary FQDN) |
| `dns.cname.fqdn` | Comma-separated FQDNs (points to primary FQDN) |
| `dns.cname.domain` | Domain for CNAME hostnames |
| `dns.cname.ttl` | TTL for CNAME records |

## Use Cases

### 1. Web Server with Aliases

```yaml
services:
  web:
    image: nginx
    labels:
      dns.enable: "true"
      dns.fqdn: "web01.example.com"
      dns.cname.hostname: "www,blog,shop"
      # Creates: web01.example.com (A/AAAA)
      # Plus CNAMEs: www → web01, blog → web01, shop → web01
```

### 2. API Versioning

```yaml
services:
  api-v2:
    image: myapi:v2
    labels:
      dns.enable: "true"
      dns.fqdn: "api-v2.example.com"
      dns.cname.hostname: "api"
      # api.example.com → api-v2.example.com (current version)
```

### 3. Multi-Zone Registration

```yaml
environment:
  DNS_ZONES: "example.com,internal.local"

services:
  database:
    labels:
      dns.enable: "true"
      dns.hostname: "postgres"
      # Creates both:
      # - postgres.example.com
      # - postgres.internal.local
```

### 4. IPv6-Only Modern Stack

```yaml
services:
  app:
    labels:
      dns.enable: "true"
      dns.aaaa.fqdn: "app.example.com"
      dns.aaaa.network: "ipv6_public"
      # Only AAAA record, specific network
```

### 5. Complex Subdomain Structure

```yaml
environment:
  DNS_ZONES: "example.com"
  EXPLICIT_SUBDOMAINS: "false"

services:
  staging-api:
    labels:
      dns.enable: "true"
      dns.hostname: "api"
      dns.domain: "staging.example.com"
      # Creates api.staging in zone example.com
```

### 6. Dual-Stack with Network Separation

```yaml
services:
  gateway:
    labels:
      dns.enable: "true"
      dns.a.fqdn: "gateway.example.com"
      dns.a.network: "ipv4_public"
      dns.aaaa.fqdn: "gateway.example.com"
      dns.aaaa.network: "ipv6_public"
      # Different networks for each IP version
    networks:
      - ipv4_public
      - ipv6_public
```

## Why HeralDNS?

### The IPv6 Reality

IPv6 gives every container a globally routable address—no NAT needed. But container restarts and ISP prefix changes make static DNS impractical. HeralDNS embraces this reality:

- Automatically updates DNS when containers restart with new IPs
- Handles ISP prefix changes transparently
- No manual intervention required
- Works with standard DNS infrastructure
- Respects IPv6's end-to-end principle

### Comparison to Alternatives

| Solution | Dynamic IPs | Existing DNS Integration | Secure Updates | Per-Container Control | Multiple Record Types |
|----------|-------------|-------------------------|----------------|----------------------|----------------------|
| **HeralDNS** | ✅ | ✅ | ✅ | ✅ | ✅ |
| Manual DNS entries | ❌ | ✅ | ✅ | ✅ | ✅ |
| Container DNS servers | ✅ | ❌ | N/A | ✅ | ⚠️ |
| DynDNS services | ⚠️ (whole host) | ⚠️ | ⚠️ | ❌ | ❌ |
| Traefik/proxy DNS | ✅ | ❌ | N/A | ✅ | ❌ |

## Advanced Usage

### SRV and Other Record Types (Coming Soon)

```yaml
services:
  app:
    labels:
      dns.srv.hostname: "_http._tcp"
      dns.srv.target: "app.example.com"
      dns.srv.port: "8080"
```

### Multiple DNS Servers (Coming Soon)

```yaml
environment:
  DNS_SERVERS: "ns1.example.com,ns2.example.com"
```

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
