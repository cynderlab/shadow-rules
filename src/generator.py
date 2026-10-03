from src.sid_manager import SidManager
from src.models import DomainEntry, CustomSignatureConfig
import logging
from datetime import datetime

# Every domain rule is emitted for each protocol that exposes the hostname.
# TLS and QUIC carry it in the ClientHello SNI: browsers send most Google,
# Meta or GenAI traffic over QUIC (HTTP/3), so TLS-only rules miss it.
# DNS sees the lookup, which still works when Encrypted Client Hello hides
# the SNI. A lookup is not proof of use (prefetching, embedded resources),
# so DNS twins carry their own msg and are limited to one alert per host
# per hour.
# Twins reuse the TLS SID plus a fixed offset so existing SIDs never move.
QUIC_SID_OFFSET = 100000
DNS_SID_OFFSET = 200000
DNS_THRESHOLD = "threshold: type limit, track by_src, count 1, seconds 3600;"


class RuleGenerator:
    def __init__(self, sid_manager: SidManager, base_sid=1000000):
        self.sid_manager = sid_manager
        self.rules = []
        self.base_sid = base_sid
        self.today = datetime.now().strftime("%Y_%m_%d")
        self.severity_levels = {
            1: "Critical",
            2: "Major",
            3: "Minor",
            4: "Informational"
        }

    def _next_sid(self):
        sid = self.sid_manager.get_sid()
        if sid - self.base_sid >= QUIC_SID_OFFSET:
            raise ValueError(
                f"SID {sid} would collide with the QUIC/DNS twin range; "
                f"raise QUIC_SID_OFFSET and DNS_SID_OFFSET"
            )
        return sid

    def _build_rule(self, category, service, domain, matching_logic, severity, priority, sid, protocol):
        severity_label = self.severity_levels.get(severity, "Minor")

        msg = f"CYNDERLAB - {category} - {service}"

        classtype = "policy-violation"
        if category == "High Risk Content":
            classtype = "bad-unknown"

        metadata = (
            f"metadata: created_at {self.today}, "
            f"updated_at {self.today}, "
            f"signature_severity {severity_label}, "
            f"vendor Cynderlab Digital SLU, "
            f"category {category}, "
            f"service {service}, "
            f"domain {domain}, "
            f"protocol {protocol};"
        )

        if protocol == "quic":
            header = f'alert quic $HOME_NET any -> $EXTERNAL_NET any (msg:"{msg}"; quic.sni;'
            sid += QUIC_SID_OFFSET
        elif protocol == "dns":
            # Clients usually ask an internal resolver, so the destination is any.
            header = f'alert dns $HOME_NET any -> any any (msg:"{msg} (DNS)"; dns.query;'
            matching_logic = f"{matching_logic} {DNS_THRESHOLD}"
            sid += DNS_SID_OFFSET
        else:
            header = f'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"{msg}"; tls.sni;'

        return (
            f'{header} {matching_logic} '
            f'classtype:{classtype}; priority:{priority}; sid:{sid}; rev:1; {metadata})'
        )

    def generate_rules(self, category, service, domain_entry: DomainEntry, severity=3, priority=3):
        domain = domain_entry.domain

        if domain_entry.is_full:
            # Exact match only
            matchings = [f'content:"{domain}"; nocase; bsize:{len(domain)};']
        else:
            # Non-full domain: two rules to respect domain boundaries
            # 1) Exact match for the bare domain (e.g. ts.net)
            # 2) Subdomain match with dot prefix (e.g. .ts.net) — won't match protechts.net
            matchings = [
                f'content:"{domain}"; nocase; bsize:{len(domain)};',
                f'content:".{domain}"; nocase; endswith;',
            ]

        # TLS rules first, then their QUIC and DNS twins in the same order.
        sids = [self._next_sid() for _ in matchings]
        return [
            self._build_rule(category, service, domain, matching, severity, priority, sid, protocol)
            for protocol in ("tls", "quic", "dns")
            for matching, sid in zip(matchings, sids)
        ]

    def generate_custom_rule(self, category, signature: CustomSignatureConfig, severity=3, priority=3):
        # Use signature-specific values if available, otherwise use category defaults
        final_severity = signature.severity if signature.severity is not None else severity
        final_priority = signature.priority if signature.priority is not None else priority

        sid = self._next_sid()
        severity_label = self.severity_levels.get(final_severity, "Minor")

        msg = f"CYNDERLAB - {category} - {signature.name}"

        # Standard metadata for custom rules
        metadata = (
            f"metadata: created_at {self.today}, "
            f"updated_at {self.today}, "
            f"signature_severity {severity_label}, "
            f"vendor Cynderlab Digital SLU, "
            f"category {category}, "
            f"custom_rule {signature.name};"
        )

        # Remove 'msg' from options if it's there to avoid duplicates
        options = signature.options
        if 'msg:' in options:
            import re
            options = re.sub(r'msg:[^;]+;', '', options).strip()

        return (
            f'alert {signature.proto} {signature.src} -> {signature.dst} '
            f'(msg:"{msg}"; {options} '
            f'classtype:policy-violation; priority:{final_priority}; sid:{sid}; rev:1; {metadata})'
        )

    def process_domains(self, category_name, service_name, domain_entries: list[DomainEntry], severity=3, priority=3):
        generated_rules = []
        for domain_entry in domain_entries:
            try:
                rules = self.generate_rules(category_name, service_name, domain_entry, severity, priority)
                generated_rules.extend(rules)
            except Exception as e:
                logging.error(f"Error generating rule for {domain_entry.domain}: {e}")
        return generated_rules
