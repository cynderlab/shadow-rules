import re
import logging
from src.models import DomainEntry

class DomainParser:
    @staticmethod
    def clean_domain(line):
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        # Remove comments at the end of the line
        if '#' in line:
            line = line.split('#')[0].strip()

        # Handle prefixes/suffixes
        if line.startswith('full:'):
            line = line[5:]

        if line.startswith('regexp:') or line.startswith('include:'):
            # Regex and includes are skipped as per requirement
            return None

        # Remove suffixes like @ads
        line = line.split('@')[0].strip()

        if not line:
            return None

        return line

    @staticmethod
    def extract_domains(content):
        domains = []
        include_keys = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if '#' in line:
                line = line.split('#')[0].strip()

            if line.startswith('include:'):
                include_name = line[8:].strip().split('@')[0].strip().split(' ')[0].strip()
                if include_name:
                    include_keys.add(include_name)
                continue

            is_full = False
            if line.startswith('full:'):
                is_full = True
                line = line[5:]

            if line.startswith('regexp:'):
                continue

            line = line.split('@')[0].strip()
            if line:
                domains.append(DomainEntry(domain=line, is_full=is_full))

        # Sort by domain for consistency
        return sorted(domains, key=lambda x: x.domain), sorted(list(include_keys))
