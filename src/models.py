from dataclasses import dataclass, field

# This can be extended by other modules (e.g., src.providers)
VALID_PROVIDERS = {"v2fly"}
VALID_SEVERITIES = {1, 2, 3, 4}
KNOWN_CATEGORY_FIELDS = {"name", "severity", "priority", "feeds", "manual_domains", "custom_signatures"}


@dataclass
class DomainEntry:
    domain: str
    is_full: bool = False


@dataclass
class ManualDomainConfig:
    name: str
    domains: list[DomainEntry] = field(default_factory=list)


@dataclass
class CustomSignatureConfig:
    name: str
    proto: str = "tcp"
    src: str = "$HOME_NET any"
    dst: str = "$EXTERNAL_NET any"
    options: str = ""
    severity: int | None = None
    priority: int | None = None


@dataclass
class FeedConfig:
    provider: str
    keys: list[str] = field(default_factory=list)


@dataclass
class CategoryConfig:
    name: str
    severity: int
    priority: int = 3
    feeds: list[FeedConfig] = field(default_factory=list)
    manual_domains: list[ManualDomainConfig] = field(default_factory=list)
    custom_signatures: list[CustomSignatureConfig] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError(f"Category config must be a dict, got {type(data).__name__}")

        unknown = set(data.keys()) - KNOWN_CATEGORY_FIELDS
        if unknown:
            raise ValueError(f"Unknown fields in category config: {unknown}")

        name = data.get("name")
        if not name or not isinstance(name, str):
            raise ValueError("Category must have a 'name' field (string)")

        severity = data.get("severity", 3)
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Category '{name}': severity must be one of {VALID_SEVERITIES}, got {severity}")

        priority = data.get("priority", severity)
        if not isinstance(priority, int) or priority < 1:
             raise ValueError(f"Category '{name}': priority must be a positive integer, got {priority}")

        feeds = []
        for provider, keys in data.get("feeds", {}).items():
            if provider not in VALID_PROVIDERS:
                raise ValueError(f"Category '{name}': unknown feed provider '{provider}'. Valid: {VALID_PROVIDERS}")
            if not isinstance(keys, list):
                raise ValueError(f"Category '{name}': feed keys for '{provider}' must be a list")
            feeds.append(FeedConfig(provider=provider, keys=keys))

        manual_domains = []
        for md_data in data.get("manual_domains", []):
            if not isinstance(md_data, dict):
                raise ValueError(f"Category '{name}': each manual domain entry must be a dict")
            md_name = md_data.get("name")
            if not md_name:
                raise ValueError(f"Category '{name}': each manual domain entry must have a 'name'")
            raw_domains = md_data.get("domains", [])
            domains = []
            for d in raw_domains:
                is_full = d.startswith("full:")
                domain = d[5:] if is_full else d
                domains.append(DomainEntry(domain=domain, is_full=is_full))
            manual_domains.append(ManualDomainConfig(name=md_name, domains=domains))

        custom_signatures = []
        for sig_data in data.get("custom_signatures", []):
            if not isinstance(sig_data, dict):
                raise ValueError(f"Category '{name}': each custom signature must be a dict")
            sig_name = sig_data.get("name")
            if not sig_name:
                raise ValueError(f"Category '{name}': each custom signature must have a 'name'")
            
            sig_severity = sig_data.get("severity")
            if sig_severity is not None and sig_severity not in VALID_SEVERITIES:
                raise ValueError(f"Signature '{sig_name}': severity must be one of {VALID_SEVERITIES}, got {sig_severity}")
            
            sig_priority = sig_data.get("priority", sig_severity)
            if sig_priority is not None and (not isinstance(sig_priority, int) or sig_priority < 1):
                raise ValueError(f"Signature '{sig_name}': priority must be a positive integer, got {sig_priority}")

            custom_signatures.append(CustomSignatureConfig(
                name=sig_name,
                proto=sig_data.get("proto", "tcp"),
                src=sig_data.get("src", "$HOME_NET any"),
                dst=sig_data.get("dst", "$EXTERNAL_NET any"),
                options=sig_data.get("options", ""),
                severity=sig_severity,
                priority=sig_priority
            ))

        return cls(name=name, severity=severity, priority=priority, feeds=feeds, manual_domains=manual_domains, custom_signatures=custom_signatures)
