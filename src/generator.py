from src.sid_manager import SidManager
from src.models import DomainEntry, CustomSignatureConfig
import logging
from datetime import datetime

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

    def _build_rule(self, category, service, domain, matching_logic, severity, priority):
        severity_label = self.severity_levels.get(severity, "Minor")
        sid = self.sid_manager.get_sid()

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
            f"domain {domain};"
        )

        return (
            f'alert tls $HOME_NET any -> $EXTERNAL_NET any '
            f'(msg:"{msg}"; tls.sni; {matching_logic} '
            f'classtype:{classtype}; priority:{priority}; sid:{sid}; rev:1; {metadata})'
        )

    def generate_rules(self, category, service, domain_entry: DomainEntry, severity=3, priority=3):
        domain = domain_entry.domain

        if domain_entry.is_full:
            # Exact match only
            matching = f'content:"{domain}"; nocase; bsize:{len(domain)};'
            return [self._build_rule(category, service, domain, matching, severity, priority)]

        # Non-full domain: two rules to respect domain boundaries
        # 1) Exact match for the bare domain (e.g. ts.net)
        exact = f'content:"{domain}"; nocase; bsize:{len(domain)};'
        # 2) Subdomain match with dot prefix (e.g. .ts.net) — won't match protechts.net
        subdomain = f'content:".{domain}"; nocase; endswith;'

        return [
            self._build_rule(category, service, domain, exact, severity, priority),
            self._build_rule(category, service, domain, subdomain, severity, priority),
        ]

    def generate_custom_rule(self, category, signature: CustomSignatureConfig, severity=3, priority=3):
        # Use signature-specific values if available, otherwise use category defaults
        final_severity = signature.severity if signature.severity is not None else severity
        final_priority = signature.priority if signature.priority is not None else priority

        sid = self.sid_manager.get_sid()
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
