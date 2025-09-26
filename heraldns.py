#!/usr/bin/env python3
"""
HeralDNS - Announce your containers to the world

Automatically registers Docker containers in DNS using dynamic updates.
Built for IPv6-first networking with support for dynamic prefix changes.

Environment Variables (Global Defaults):
    DNS_PROVIDER: DNS provider type - 'gss-tsig' or 'tsig'
    DNS_SERVER: DNS server FQDN or IP address
    DNS_ZONES: Comma-separated list of DNS zones (e.g., example.com,internal.local)
    
    # GSS-TSIG (Active Directory) specific:
    KRB_PRINCIPAL: Kerberos principal (e.g., svc-docker-dns@EXAMPLE.COM)
    KRB_PASSWORD: Kerberos password (OR use keytab)
    KRB_KEYTAB_BASE64: Base64-encoded keytab file (OR use password)
    
    # TSIG (BIND/PowerDNS) specific:
    TSIG_KEY_NAME: TSIG key name
    TSIG_KEY_SECRET: Base64-encoded TSIG key
    TSIG_ALGORITHM: TSIG algorithm (default: hmac-sha256)
    
    # Registration settings:
    REGISTER_ALL: Register all containers by default (default: false)
    EXPLICIT_SUBDOMAINS: Require exact zone match vs allow subdomains (default: false)
    DEFAULT_NETWORK: Default Docker network(s) to check for IPs (comma-separated)
    DNS_TTL: Default TTL for DNS records in seconds (default: 300)
    POLL_INTERVAL: Seconds between checks (default: 60)

Container Labels:
    dns.enable: "true" to register (required unless REGISTER_ALL=true)
    dns.ignore: "true" to skip registration
    
    # Record specification (without type = both A and AAAA):
    dns.fqdn: Full FQDN (e.g., api.staging.example.com)
    dns.hostname: Hostname or record name (e.g., api or api.staging)
    dns.domain: Domain or zone name (e.g., example.com or staging.example.com)
    
    # Type-specific records:
    dns.a.fqdn / dns.a.hostname / dns.a.domain: A record only
    dns.aaaa.fqdn / dns.aaaa.hostname / dns.aaaa.domain: AAAA record only
    
    # CNAME records (always point to primary FQDN):
    dns.cname.hostname: Comma-separated hostnames for CNAMEs
    dns.cname.fqdn: Comma-separated FQDNs for CNAMEs
    
    # Per-record overrides:
    dns.<type>.network: Network(s) to use for this record type
    dns.<type>.ttl: TTL for this record type
"""

import os
import sys
import time
import uuid
import base64
import socket
import logging
import subprocess
from typing import Dict, Optional, Tuple, List, Set
from dataclasses import dataclass
from collections import defaultdict

import docker
import dns.name
import dns.update
import dns.query
import dns.rdatatype
import dns.rdataclass
import dns.message
import dns.tsigkeyring

# GSS-TSIG imports (optional)
try:
    import gssapi
    import dns.tsig
    import dns.rdtypes.ANY.TKEY
    GSSAPI_AVAILABLE = True
except ImportError:
    GSSAPI_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    """Represents a DNS record to be created/updated"""
    record_name: str  # e.g., "api.staging" or "www"
    zone: str  # e.g., "example.com"
    record_type: str  # "A", "AAAA", "CNAME"
    value: str  # IP address or target hostname
    ttl: int = 300
    
    @property
    def fqdn(self) -> str:
        """Full FQDN for this record"""
        if self.record_name:
            return f"{self.record_name}.{self.zone}"
        return self.zone


class KerberosAuth:
    """Handles Kerberos authentication and ticket management"""
    
    def __init__(self, principal: str, password: Optional[str] = None, keytab_path: str = '/keytab'):
        self.principal = principal
        self.password = password
        self.keytab_path = keytab_path
        
        if password:
            log.info("Using password authentication")
        else:
            self._ensure_keytab()
        
    def _ensure_keytab(self):
        """Decode keytab from env var if provided"""
        keytab_b64 = os.environ.get('KRB_KEYTAB_BASE64')
        if keytab_b64 and not os.path.exists(self.keytab_path):
            keytab_data = base64.b64decode(keytab_b64)
            os.makedirs(os.path.dirname(self.keytab_path), exist_ok=True)
            with open(self.keytab_path, 'wb') as f:
                f.write(keytab_data)
            os.chmod(self.keytab_path, 0o600)
            log.info(f"Decoded keytab to {self.keytab_path}")
    
    def get_ticket(self):
        """Acquire Kerberos ticket using keytab or password"""
        try:
            if self.password:
                process = subprocess.Popen(
                    ['kinit', self.principal],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(input=self.password)
                if process.returncode != 0:
                    raise RuntimeError(f"kinit failed: {stderr}")
            else:
                result = subprocess.run(
                    ['kinit', '-k', '-t', self.keytab_path, self.principal],
                    capture_output=True,
                    text=True,
                    check=True
                )
            log.info(f"Acquired Kerberos ticket for {self.principal}")
        except (subprocess.CalledProcessError, RuntimeError) as e:
            log.error(f"Failed to acquire Kerberos ticket: {e}")
            raise
    
    def check_ticket_validity(self) -> bool:
        """Check if current ticket is valid"""
        result = subprocess.run(['klist', '-s'], capture_output=True)
        return result.returncode == 0
    
    def ensure_valid_ticket(self):
        """Ensure we have a valid Kerberos ticket"""
        if not self.check_ticket_validity():
            log.info("Kerberos ticket expired or missing, acquiring new ticket")
            self.get_ticket()


class GssTsigClient:
    """GSS-TSIG DNS update client for Active Directory"""
    
    def __init__(self, server_fqdn: str, server_ip: str):
        if not GSSAPI_AVAILABLE:
            raise RuntimeError("GSS-TSIG requires gssapi library (pip install gssapi)")
        
        self.server_fqdn = server_fqdn
        self.server_ip = server_ip
        self.keyring = None
        self.keyname = None
        
    def _build_tkey_query(self, token: bytes, keyring, keyname):
        """Build TKEY query for GSS-TSIG negotiation"""
        inception_time = int(time.time())
        tkey = dns.rdtypes.ANY.TKEY.TKEY(
            dns.rdataclass.ANY,
            dns.rdatatype.TKEY,
            dns.name.from_text('gss-tsig.'),
            inception_time,
            inception_time,
            3,
            dns.rcode.NOERROR,
            token,
            b''
        )
        
        tkey_query = dns.message.make_query(
            keyname,
            dns.rdatatype.RdataType.TKEY,
            dns.rdataclass.RdataClass.ANY
        )
        
        rrset = tkey_query.find_rrset(
            tkey_query.additional,
            keyname,
            dns.rdataclass.RdataClass.ANY,
            dns.rdatatype.RdataType.TKEY,
            create=True
        )
        rrset.add(tkey)
        tkey_query.keyring = keyring
        
        return tkey_query
    
    def initialize_context(self):
        """Initialize GSS-TSIG security context"""
        log.info(f"Initializing GSS-TSIG context with {self.server_fqdn}")
        
        keyname = dns.name.from_text(f"{uuid.uuid4()}")
        spn = gssapi.Name(
            f'DNS@{self.server_fqdn}',
            gssapi.NameType.hostbased_service
        )
        
        client_ctx = gssapi.SecurityContext(name=spn, usage='initiate')
        tsig_key = dns.tsig.Key(keyname, client_ctx, 'gss-tsig.')
        
        keyring = dns.tsigkeyring.from_text({})
        keyring[keyname] = tsig_key
        keyring = dns.tsig.GSSTSigAdapter(keyring)
        
        token = client_ctx.step()
        
        while not client_ctx.complete:
            tkey_query = self._build_tkey_query(token, keyring, keyname)
            response = dns.query.tcp(tkey_query, self.server_ip, timeout=10, port=53)
            if not client_ctx.complete:
                token = client_ctx.step(response.answer[0][0].key)
        
        self.keyring = keyring
        self.keyname = keyname
        log.info("GSS-TSIG context initialized successfully")
    
    def update_records(self, records: List[DNSRecord]):
        """Update multiple DNS records"""
        if not self.keyring:
            raise RuntimeError("GSS-TSIG context not initialized")
        
        # Group records by zone
        by_zone = defaultdict(list)
        for record in records:
            by_zone[record.zone].append(record)
        
        # Send one update per zone
        for zone, zone_records in by_zone.items():
            update = dns.update.UpdateMessage(
                zone=zone,
                keyring=self.keyring,
                keyname=self.keyname,
                keyalgorithm='gss-tsig.'
            )
            
            for record in zone_records:
                log.info(f"Adding {record.record_type} record: {record.fqdn} -> {record.value}")
                update.replace(record.fqdn, record.ttl, record.record_type, record.value)
            
            response = dns.query.tcp(update, self.server_ip)
            
            if response.rcode() != 0:
                error = dns.rcode.to_text(response.rcode())
                log.error(f"DNS update failed for zone {zone}: {error}")
                raise RuntimeError(f"DNS update failed: {error}")
            
            log.info(f"Successfully updated {len(zone_records)} records in zone {zone}")
    
    def delete_records(self, records: List[DNSRecord]):
        """Delete DNS records"""
        if not self.keyring:
            raise RuntimeError("GSS-TSIG context not initialized")
        
        by_zone = defaultdict(list)
        for record in records:
            by_zone[record.zone].append(record)
        
        for zone, zone_records in by_zone.items():
            update = dns.update.UpdateMessage(
                zone=zone,
                keyring=self.keyring,
                keyname=self.keyname,
                keyalgorithm='gss-tsig.'
            )
            
            for record in zone_records:
                log.info(f"Deleting {record.record_type} record: {record.fqdn}")
                update.delete(record.fqdn, record.record_type)
            
            response = dns.query.tcp(update, self.server_ip)
            
            if response.rcode() != 0:
                error = dns.rcode.to_text(response.rcode())
                log.error(f"DNS delete failed for zone {zone}: {error}")


class TsigClient:
    """TSIG DNS update client for BIND/PowerDNS"""
    
    def __init__(self, server: str, key_name: str, key_secret: str, algorithm: str = 'hmac-sha256'):
        self.server = server
        self.keyring = dns.tsigkeyring.from_text({key_name: key_secret})
        self.key_name = key_name
        self.algorithm = algorithm
        log.info(f"Initialized TSIG client with key {key_name}")
    
    def update_records(self, records: List[DNSRecord]):
        """Update multiple DNS records"""
        by_zone = defaultdict(list)
        for record in records:
            by_zone[record.zone].append(record)
        
        for zone, zone_records in by_zone.items():
            update = dns.update.UpdateMessage(
                zone=zone,
                keyring=self.keyring,
                keyalgorithm=self.algorithm
            )
            
            for record in zone_records:
                log.info(f"Adding {record.record_type} record: {record.fqdn} -> {record.value}")
                update.replace(record.fqdn, record.ttl, record.record_type, record.value)
            
            response = dns.query.tcp(update, self.server)
            
            if response.rcode() != 0:
                error = dns.rcode.to_text(response.rcode())
                log.error(f"DNS update failed for zone {zone}: {error}")
                raise RuntimeError(f"DNS update failed: {error}")
            
            log.info(f"Successfully updated {len(zone_records)} records in zone {zone}")
    
    def delete_records(self, records: List[DNSRecord]):
        """Delete DNS records"""
        by_zone = defaultdict(list)
        for record in records:
            by_zone[record.zone].append(record)
        
        for zone, zone_records in by_zone.items():
            update = dns.update.UpdateMessage(
                zone=zone,
                keyring=self.keyring,
                keyalgorithm=self.algorithm
            )
            
            for record in zone_records:
                log.info(f"Deleting {record.record_type} record: {record.fqdn}")
                update.delete(record.fqdn, record.record_type)
            
            response = dns.query.tcp(update, self.server)
            
            if response.rcode() != 0:
                error = dns.rcode.to_text(response.rcode())
                log.error(f"DNS delete failed for zone {zone}: {error}")


class ContainerDNSExtractor:
    """Extracts DNS records from container labels and network info"""
    
    def __init__(self, zones: List[str], explicit_subdomains: bool, default_ttl: int,
                 default_networks: List[str], register_all: bool):
        self.zones = zones
        self.explicit_subdomains = explicit_subdomains
        self.default_ttl = default_ttl
        self.default_networks = default_networks
        self.register_all = register_all
    
    def _find_matching_zone(self, domain: str) -> Optional[str]:
        """Find which zone this domain belongs to"""
        domain_lower = domain.lower().rstrip('.')
        
        for zone in self.zones:
            zone_lower = zone.lower().rstrip('.')
            
            if self.explicit_subdomains:
                # Exact match only
                if domain_lower == zone_lower:
                    return zone
            else:
                # Allow subdomains
                if domain_lower == zone_lower or domain_lower.endswith('.' + zone_lower):
                    return zone
        
        return None
    
    def _parse_fqdn(self, fqdn: str) -> Optional[Tuple[str, str, str]]:
        """
        Parse FQDN into (record_name, zone, matched_zone)
        Returns None if no zone matches
        """
        fqdn = fqdn.rstrip('.')
        
        # Find matching zone
        for zone in self.zones:
            zone_lower = zone.lower().rstrip('.')
            fqdn_lower = fqdn.lower()
            
            if self.explicit_subdomains:
                # Must exactly match zone
                if fqdn_lower.endswith('.' + zone_lower) or fqdn_lower == zone_lower:
                    matched_zone = zone
                    record_name = fqdn[:-(len(zone)+1)] if fqdn_lower != zone_lower else ''
                    return (record_name, zone, matched_zone)
            else:
                # Allow subdomains
                if fqdn_lower.endswith('.' + zone_lower):
                    matched_zone = zone
                    record_name = fqdn[:-(len(zone)+1)]
                    return (record_name, zone, matched_zone)
                elif fqdn_lower == zone_lower:
                    matched_zone = zone
                    return ('', zone, matched_zone)
        
        return None
    
    def _get_ips_from_container(self, container, networks: List[str]) -> Tuple[Optional[str], Optional[str]]:
        """Get IPv4 and IPv6 from container"""
        ipv4 = None
        ipv6 = None
        
        try:
            container.reload()
            container_networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
            
            if networks:
                container_networks = {k: v for k, v in container_networks.items() if k in networks}
            
            for network_name, network_info in container_networks.items():
                if not ipv4 and network_info.get('IPAddress'):
                    ipv4 = network_info['IPAddress']
                    log.debug(f"Found IPv4 {ipv4} on network {network_name}")
                
                if not ipv6 and network_info.get('GlobalIPv6Address'):
                    ipv6 = network_info['GlobalIPv6Address']
                    log.debug(f"Found IPv6 {ipv6} on network {network_name}")
        
        except Exception as e:
            log.error(f"Error getting IPs for {container.name}: {e}")
        
        return ipv4, ipv6
    
    def extract_records(self, container) -> List[DNSRecord]:
        """Extract all DNS records for a container"""
        labels = container.labels
        
        # Check if should be registered
        if labels.get('dns.ignore', '').lower() == 'true':
            return []
        
        if not self.register_all and labels.get('dns.enable', '').lower() != 'true':
            return []
        
        records = []
        primary_fqdn = None
        
        # Determine primary FQDN (for A/AAAA records and CNAME targets)
        if 'dns.fqdn' in labels:
            if 'dns.hostname' in labels or 'dns.domain' in labels:
                log.warning(f"Container {container.name}: dns.fqdn specified, ignoring dns.hostname/dns.domain")
            primary_fqdn = labels['dns.fqdn']
        elif 'dns.hostname' in labels or 'dns.domain' in labels:
            hostname = labels.get('dns.hostname', container.name)
            domain = labels.get('dns.domain', '')
            if domain:
                primary_fqdn = f"{hostname}.{domain}" if hostname else domain
            else:
                # No domain specified - update in all zones
                hostname_val = labels.get('dns.hostname', container.name)
                for zone in self.zones:
                    fqdn = f"{hostname_val}.{zone}"
                    self._add_standard_records(container, fqdn, 'dns', records)
                return records
        elif self.register_all:
            # Use container name in all zones
            for zone in self.zones:
                fqdn = f"{container.name}.{zone}"
                self._add_standard_records(container, fqdn, 'dns', records)
            return records
        
        if primary_fqdn:
            # Add A/AAAA records for primary FQDN
            self._add_standard_records(container, primary_fqdn, 'dns', records)
            
            # Add type-specific records
            for record_type in ['a', 'aaaa']:
                type_prefix = f'dns.{record_type}'
                if f'{type_prefix}.fqdn' in labels:
                    self._add_typed_record(container, labels[f'{type_prefix}.fqdn'], 
                                         record_type.upper(), type_prefix, records)
                elif f'{type_prefix}.hostname' in labels or f'{type_prefix}.domain' in labels:
                    hostname = labels.get(f'{type_prefix}.hostname', container.name)
                    domain = labels.get(f'{type_prefix}.domain', '')
                    if domain:
                        fqdn = f"{hostname}.{domain}"
                        self._add_typed_record(container, fqdn, record_type.upper(), 
                                             type_prefix, records)
            
            # Add CNAME records pointing to primary FQDN
            self._add_cname_records(container, primary_fqdn, records)
        
        return records
    
    def _add_standard_records(self, container, fqdn: str, label_prefix: str, records: List[DNSRecord]):
        """Add A and/or AAAA records"""
        parsed = self._parse_fqdn(fqdn)
        if not parsed:
            log.error(f"Container {container.name}: FQDN {fqdn} does not match any configured zones")
            return
        
        record_name, zone, _ = parsed
        
        # Get networks
        networks = container.labels.get(f'{label_prefix}.network', '')
        networks = [n.strip() for n in networks.split(',') if n.strip()] if networks else self.default_networks
        
        # Get TTL
        ttl = int(container.labels.get(f'{label_prefix}.ttl', self.default_ttl))
        
        # Get IPs
        ipv4, ipv6 = self._get_ips_from_container(container, networks)
        
        if ipv4:
            records.append(DNSRecord(record_name, zone, 'A', ipv4, ttl))
        if ipv6:
            records.append(DNSRecord(record_name, zone, 'AAAA', ipv6, ttl))
    
    def _add_typed_record(self, container, fqdn: str, record_type: str, 
                         label_prefix: str, records: List[DNSRecord]):
        """Add type-specific record (A or AAAA)"""
        parsed = self._parse_fqdn(fqdn)
        if not parsed:
            log.error(f"Container {container.name}: FQDN {fqdn} does not match any configured zones")
            return
        
        record_name, zone, _ = parsed
        
        networks = container.labels.get(f'{label_prefix}.network', '')
        networks = [n.strip() for n in networks.split(',') if n.strip()] if networks else self.default_networks
        
        ttl = int(container.labels.get(f'{label_prefix}.ttl', self.default_ttl))
        
        ipv4, ipv6 = self._get_ips_from_container(container, networks)
        
        if record_type == 'A' and ipv4:
            records.append(DNSRecord(record_name, zone, 'A', ipv4, ttl))
        elif record_type == 'AAAA' and ipv6:
            records.append(DNSRecord(record_name, zone, 'AAAA', ipv6, ttl))
    
    def _add_cname_records(self, container, target_fqdn: str, records: List[DNSRecord]):
        """Add CNAME records pointing to target_fqdn"""
        labels = container.labels
        ttl = int(labels.get('dns.cname.ttl', self.default_ttl))
        
        cnames = []
        
        # Get CNAMEs from hostname labels
        if 'dns.cname.hostname' in labels:
            hostnames = [h.strip() for h in labels['dns.cname.hostname'].split(',')]
            domain = labels.get('dns.cname.domain', '')
            if domain:
                cnames.extend([f"{h}.{domain}" for h in hostnames])
            else:
                # Add to all zones
                for zone in self.zones:
                    cnames.extend([f"{h}.{zone}" for h in hostnames])
        
        # Get CNAMEs from FQDN labels
        if 'dns.cname.fqdn' in labels:
            fqdns = [f.strip() for f in labels['dns.cname.fqdn'].split(',')]
            cnames.extend(fqdns)
        
        # Create CNAME records
        for cname_fqdn in cnames:
            parsed = self._parse_fqdn(cname_fqdn)
            if not parsed:
                log.error(f"Container {container.name}: CNAME {cname_fqdn} does not match any configured zones")
                continue
            
            record_name, zone, _ = parsed
            # CNAME value should be the target FQDN with trailing dot
            target_with_dot = target_fqdn.rstrip('.') + '.'
            records.append(DNSRecord(record_name, zone, 'CNAME', target_with_dot, ttl))


class DockerDNSSync:
    """Main sync orchestrator"""
    
    def __init__(self, dns_client, kerberos: Optional[KerberosAuth], 
                 extractor: ContainerDNSExtractor):
        self.dns_client = dns_client
        self.kerberos = kerberos
        self.extractor = extractor
        self.docker_client = docker.from_env()
        self.known_records: Dict[str, Set[str]] = {}  # container_id -> set of record strings
    
    def _record_key(self, record: DNSRecord) -> str:
        """Generate unique key for record"""
        return f"{record.record_type}:{record.fqdn}:{record.value}"
    
    def sync_container(self, container):
        """Sync single container's DNS records"""
        try:
            records = self.extractor.extract_records(container)
        except Exception as e:
            log.error(f"Error extracting records for {container.name}: {e}")
            return
        
        if not records:
            return
        
        container_id = container.id
        new_record_keys = {self._record_key(r) for r in records}
        old_record_keys = self.known_records.get(container_id, set())
        
        if new_record_keys == old_record_keys:
            return  # No changes
        
        # Ensure valid Kerberos ticket if using GSS-TSIG
        if self.kerberos:
            self.kerberos.ensure_valid_ticket()
        
        # Update DNS
        try:
            self.dns_client.update_records(records)
            self.known_records[container_id] = new_record_keys
        except Exception as e:
            log.error(f"Failed to update DNS for {container.name}: {e}")
            if self.kerberos and ("GSS" in str(e) or "ticket" in str(e).lower()):
                log.info("Re-initializing authentication")
                self.kerberos.get_ticket()
                if hasattr(self.dns_client, 'initialize_context'):
                    self.dns_client.initialize_context()
    
    def sync_all_containers(self):
        """Sync all running containers"""
        try:
            containers = self.docker_client.containers.list()
            current_ids = set()
            
            for container in containers:
                current_ids.add(container.id)
                self.sync_container(container)
            
            # Remove records for stopped containers
            stopped_ids = set(self.known_records.keys()) - current_ids
            for container_id in stopped_ids:
                log.info(f"Container {container_id[:12]} stopped, cleaning up DNS")
                del self.known_records[container_id]
                # Note: actual DNS cleanup would require knowing which records to delete
        
        except Exception as e:
            log.error(f"Error syncing containers: {e}")
    
    def run(self, poll_interval: int):
        """Main loop"""
        log.info(f"Starting HeralDNS (polling every {poll_interval}s)")
        
        while True:
            self.sync_all_containers()
            time.sleep(poll_interval)


def main():
    # Load configuration
    dns_provider = os.environ.get('DNS_PROVIDER', '').lower()
    dns_server = os.environ.get('DNS_SERVER')
    dns_zones_str = os.environ.get('DNS_ZONES', '')
    dns_zones = [z.strip() for z in dns_zones_str.split(',') if z.strip()]
    
    register_all = os.environ.get('REGISTER_ALL', 'false').lower() == 'true'
    explicit_subdomains = os.environ.get('EXPLICIT_SUBDOMAINS', 'false').lower() == 'true'
    
    default_networks_str = os.environ.get('DEFAULT_NETWORK', '')
    default_networks = [n.strip() for n in default_networks_str.split(',') if n.strip()]
    
    default_ttl = int(os.environ.get('DNS_TTL', '300'))
    poll_interval = int(os.environ.get('POLL_INTERVAL', '60'))
    
    # Validate
    if not dns_provider or dns_provider not in ['gss-tsig', 'tsig']:
        log.error("DNS_PROVIDER must be 'gss-tsig' or 'tsig'")
        sys.exit(1)
    
    if not dns_server or not dns_zones:
        log.error("DNS_SERVER and DNS_ZONES are required")
        sys.exit(1)
    
    log.info(f"HeralDNS Configuration:")
    log.info(f"  Provider: {dns_provider}")
    log.info(f"  Server: {dns_server}")
    log.info(f"  Zones: {dns_zones}")
    log.info(f"  Register All: {register_all}")
    log.info(f"  Explicit Subdomains: {explicit_subdomains}")
    log.info(f"  Default Networks: {default_networks or 'all'}")
    
    # Initialize DNS client
    dns_client = None
    kerberos = None
    
    if dns_provider == 'gss-tsig':
        # GSS-TSIG for Active Directory
        krb_principal = os.environ.get('KRB_PRINCIPAL')
        krb_password = os.environ.get('KRB_PASSWORD')
        
        if not krb_principal:
            log.error("KRB_PRINCIPAL required for GSS-TSIG")
            sys.exit(1)
        
        if not krb_password and not os.environ.get('KRB_KEYTAB_BASE64') and not os.path.exists('/keytab'):
            log.error("KRB_PASSWORD, KRB_KEYTAB_BASE64, or keytab file required for GSS-TSIG")
            sys.exit(1)
        
        # Resolve FQDN if only IP provided
        dns_server_fqdn = dns_server
        dns_server_ip = dns_server
        
        if not dns_server.replace('.', '').isdigit():  # Looks like FQDN
            try:
                dns_server_ip = socket.gethostbyname(dns_server)
                log.info(f"Resolved DNS server IP: {dns_server_ip}")
            except Exception as e:
                log.error(f"Could not resolve IP for {dns_server}: {e}")
                sys.exit(1)
        else:  # Looks like IP
            try:
                dns_server_fqdn = socket.getfqdn(dns_server)
                log.info(f"Resolved DNS server FQDN: {dns_server_fqdn}")
            except Exception as e:
                log.error(f"Could not resolve FQDN for {dns_server}: {e}")
                sys.exit(1)
        
        kerberos = KerberosAuth(krb_principal, krb_password)
        kerberos.get_ticket()
        
        dns_client = GssTsigClient(dns_server_fqdn, dns_server_ip)
        dns_client.initialize_context()
    
    elif dns_provider == 'tsig':
        # TSIG for BIND/PowerDNS
        tsig_key_name = os.environ.get('TSIG_KEY_NAME')
        tsig_key_secret = os.environ.get('TSIG_KEY_SECRET')
        tsig_algorithm = os.environ.get('TSIG_ALGORITHM', 'hmac-sha256')
        
        if not tsig_key_name or not tsig_key_secret:
            log.error("TSIG_KEY_NAME and TSIG_KEY_SECRET required for TSIG")
            sys.exit(1)
        
        dns_client = TsigClient(dns_server, tsig_key_name, tsig_key_secret, tsig_algorithm)
    
    # Initialize extractor
    extractor = ContainerDNSExtractor(
        dns_zones, explicit_subdomains, default_ttl,
        default_networks, register_all
    )
    
    # Start sync
    sync = DockerDNSSync(dns_client, kerberos, extractor)
    sync.run(poll_interval)


if __name__ == '__main__':
    main()
