from src.sid_manager import SidManager
from src.generator import RuleGenerator
from src.parser import DomainParser
from src.models import DomainEntry
from src.generator import QUIC_SID_OFFSET, DNS_SID_OFFSET


def make_generator():
    sid_mgr = SidManager(start_sid=9000)
    return RuleGenerator(sid_mgr), sid_mgr


def by_proto(rules, proto):
    return [r for r in rules if r.startswith(f"alert {proto} ")]


def sid_of(rule):
    return int(rule.split("sid:")[1].split(";")[0])


class TestGenerateRules:
    def test_full_match_single_rule_with_bsize(self):
        gen, _ = make_generator()
        domain_entry = DomainEntry("exact.example.com", is_full=True)
        rules = by_proto(gen.generate_rules("TestCat", "TestSvc", domain_entry), "tls")
        assert len(rules) == 1
        assert 'bsize:' in rules[0]
        assert 'isdataat:' not in rules[0]
        assert 'endswith;' not in rules[0]

    def test_full_match_bsize_equals_domain_length(self):
        gen, _ = make_generator()
        domain = "remotedesktop.google.com"
        domain_entry = DomainEntry(domain, is_full=True)
        rules = gen.generate_rules("Cat", "Svc", domain_entry)
        assert f"bsize:{len(domain)};" in rules[0]

    def test_full_match_content_string(self):
        gen, _ = make_generator()
        domain = "assist.zoho.com"
        domain_entry = DomainEntry(domain, is_full=True)
        rules = gen.generate_rules("Cat", "Svc", domain_entry)
        assert f'content:"{domain}";' in rules[0]
        assert "full:" not in rules[0]

    def test_non_full_generates_two_rules(self):
        gen, _ = make_generator()
        domain_entry = DomainEntry("tailscale.com")
        rules = by_proto(gen.generate_rules("Cat", "Svc", domain_entry), "tls")
        assert len(rules) == 2

    def test_non_full_exact_match_rule(self):
        """First rule matches the bare domain exactly via bsize."""
        gen, _ = make_generator()
        domain = "ts.net"
        domain_entry = DomainEntry(domain)
        rules = gen.generate_rules("Cat", "Svc", domain_entry)
        exact_rule = rules[0]
        assert f'content:"{domain}";' in exact_rule
        assert f'bsize:{len(domain)};' in exact_rule
        assert 'endswith;' not in exact_rule

    def test_non_full_subdomain_match_rule(self):
        """Second rule matches subdomains with dot prefix."""
        gen, _ = make_generator()
        domain = "ts.net"
        domain_entry = DomainEntry(domain)
        rules = gen.generate_rules("Cat", "Svc", domain_entry)
        sub_rule = rules[1]
        assert f'content:".{domain}";' in sub_rule
        assert 'endswith;' in sub_rule
        assert 'bsize:' not in sub_rule

    def test_non_full_no_bare_endswith(self):
        """Non-full rules must NOT have bare endswith without dot prefix."""
        gen, _ = make_generator()
        domain_entry = DomainEntry("ts.net")
        rules = gen.generate_rules("Cat", "Svc", domain_entry)
        for rule in rules:
            # Should never have content:"ts.net" + endswith (without dot)
            assert 'content:"ts.net"; nocase; endswith;' not in rule

    def test_non_full_no_false_positive_on_substring(self):
        """Ensure 'protechts.net' would NOT match rules for 'ts.net'.
        The exact rule uses bsize (so protechts.net is too long).
        The subdomain rule requires '.ts.net' suffix (protechts.net has no dot before ts.net)."""
        gen, _ = make_generator()
        domain_entry = DomainEntry("ts.net")
        rules = gen.generate_rules("Cat", "Svc", domain_entry)
        exact_rule = rules[0]
        sub_rule = rules[1]
        # Exact rule: bsize:6 means only "ts.net" (6 chars) matches
        assert "bsize:6;" in exact_rule
        # Subdomain rule: content:".ts.net" won't match "protechts.net"
        assert 'content:".ts.net";' in sub_rule

    def test_severity_critical(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("Cat", "Svc", DomainEntry("a.com"), severity=1)
        assert all("signature_severity Critical" in r for r in rules)

    def test_severity_major(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("Cat", "Svc", DomainEntry("a.com"), severity=2)
        assert all("signature_severity Major" in r for r in rules)

    def test_severity_minor(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("Cat", "Svc", DomainEntry("a.com"), severity=3)
        assert all("signature_severity Minor" in r for r in rules)

    def test_severity_informational(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("Cat", "Svc", DomainEntry("a.com"), severity=4)
        assert all("signature_severity Informational" in r for r in rules)

    def test_default_severity_is_minor(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("Cat", "Svc", DomainEntry("a.com"))
        assert all("signature_severity Minor" in r for r in rules)

    def test_metadata_fields(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("MyCat", "MySvc", DomainEntry("test.com"))
        for rule in rules:
            assert "category MyCat" in rule
            assert "service MySvc" in rule
            assert "domain test.com" in rule
            assert "vendor Cynderlab Digital SLU" in rule
            assert 'msg:"CYNDERLAB -' in rule

    def test_high_risk_classtype(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("High Risk Content", "Svc", DomainEntry("evil.com"))
        assert all("classtype:bad-unknown" in r for r in rules)

    def test_normal_classtype(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("Normal", "Svc", DomainEntry("a.com"))
        assert all("classtype:policy-violation" in r for r in rules)

    def test_tls_rules_use_tls_sni(self):
        gen, _ = make_generator()
        for entry in [DomainEntry("a.com"), DomainEntry("b.com", is_full=True)]:
            rules = gen.generate_rules("Cat", "Svc", entry)
            for rule in by_proto(rules, "tls"):
                assert "tls.sni;" in rule
                assert "protocol tls;" in rule

    def test_tls_rules_come_first(self):
        """rules[0] and rules[1] stay the TLS exact and subdomain rules."""
        gen, _ = make_generator()
        rules = gen.generate_rules("Cat", "Svc", DomainEntry("a.com"))
        assert [r.split(" ")[1] for r in rules] == ["tls", "tls", "quic", "quic", "dns", "dns"]


class TestProtocolTwins:
    """Every TLS rule has a QUIC and a DNS twin with the same matching."""

    def test_each_tls_rule_has_quic_and_dns_twin(self):
        gen, _ = make_generator()
        for entry in [DomainEntry("a.com"), DomainEntry("b.com", is_full=True)]:
            rules = gen.generate_rules("Cat", "Svc", entry)
            assert len(by_proto(rules, "quic")) == len(by_proto(rules, "tls"))
            assert len(by_proto(rules, "dns")) == len(by_proto(rules, "tls"))
            assert len(rules) == 3 * len(by_proto(rules, "tls"))

    def test_quic_twin_uses_quic_sni_and_same_msg(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("GenAI", "Google Deepmind", DomainEntry("gemini.google.com"))
        tls, quic = by_proto(rules, "tls"), by_proto(rules, "quic")
        for t, q in zip(tls, quic):
            assert q.startswith("alert quic $HOME_NET any -> $EXTERNAL_NET any ")
            assert "quic.sni;" in q and "tls.sni" not in q
            assert 'msg:"CYNDERLAB - GenAI - Google Deepmind";' in q
            assert "protocol quic;" in q
            assert t.split("sni;")[1].split("classtype")[0] == q.split("sni;")[1].split("classtype")[0]

    def test_dns_twin_matches_query_with_own_msg_and_threshold(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("GenAI", "Google Deepmind", DomainEntry("gemini.google.com"))
        dns = by_proto(rules, "dns")
        assert 'content:"gemini.google.com"; nocase; bsize:17;' in dns[0]
        assert 'content:".gemini.google.com"; nocase; endswith;' in dns[1]
        for d in dns:
            # Clients ask an internal resolver: destination must not be $EXTERNAL_NET.
            assert d.startswith("alert dns $HOME_NET any -> any any ")
            assert "dns.query;" in d
            assert 'msg:"CYNDERLAB - GenAI - Google Deepmind (DNS)";' in d
            assert "threshold: type limit, track by_src, count 1, seconds 3600;" in d
            assert "protocol dns;" in d

    def test_twin_sids_are_tls_sid_plus_offset(self):
        gen, _ = make_generator()
        rules = gen.generate_rules("Cat", "Svc", DomainEntry("a.com"))
        tls = [sid_of(r) for r in by_proto(rules, "tls")]
        assert [sid_of(r) for r in by_proto(rules, "quic")] == [s + QUIC_SID_OFFSET for s in tls]
        assert [sid_of(r) for r in by_proto(rules, "dns")] == [s + DNS_SID_OFFSET for s in tls]

    def test_twins_do_not_consume_base_sids(self):
        """Adding twins must not shift the SIDs of existing TLS rules."""
        gen, mgr = make_generator()
        gen.generate_rules("Cat", "Svc", DomainEntry("a.com"))
        assert mgr.next_sid == 9002

    def test_sid_reaching_twin_range_fails(self):
        mgr = SidManager(start_sid=1000000 + QUIC_SID_OFFSET)
        gen = RuleGenerator(mgr)
        try:
            gen.generate_rules("Cat", "Svc", DomainEntry("a.com"))
        except ValueError as e:
            assert "twin range" in str(e)
        else:
            raise AssertionError("expected ValueError")

    def test_unique_sids_across_rules(self):
        gen, _ = make_generator()
        all_rules = []
        for d in ["a.com", "b.com", "c.net"]:
            all_rules.extend(gen.generate_rules("Cat", "Svc", DomainEntry(d)))
        sids = []
        for rule in all_rules:
            sid_part = rule.split("sid:")[1].split(";")[0]
            sids.append(int(sid_part))
        assert len(sids) == len(set(sids))


class TestProcessDomains:
    def test_generates_correct_rule_count(self):
        """Non-full domains generate 2 rules each, full domains generate 1."""
        gen, _ = make_generator()
        domains = [DomainEntry("a.com"), DomainEntry("b.com"), DomainEntry("c.com", is_full=True)]
        rules = gen.process_domains("Cat", "Svc", domains)
        # (2 non-full * 2 rules + 1 full * 1 rule) * 3 protocols = 15
        assert len(by_proto(rules, "tls")) == 5
        assert len(rules) == 15


class TestFullPrefixEndToEnd:
    """Parser -> Generator pipeline: ensure full: flag flows correctly."""

    def test_parser_full_flag_produces_exact_match_rule(self):
        content = "full:remotedesktop.google.com\ntalkgadget.google.com\n"
        domains, _ = DomainParser.extract_domains(content)

        gen, _ = make_generator()
        rules = by_proto(gen.process_domains("Remote", "Chrome", domains), "tls")

        full_rules = [r for r in rules if "remotedesktop.google.com" in r]
        wild_rules = [r for r in rules if "talkgadget.google.com" in r]

        # full: domain -> 1 rule with bsize
        assert len(full_rules) == 1
        assert f"bsize:{len('remotedesktop.google.com')};" in full_rules[0]
        assert "isdataat:" not in full_rules[0]
        assert "endswith;" not in full_rules[0]

        # non-full domain -> 2 rules (exact + subdomain)
        assert len(wild_rules) == 2
        assert any("endswith;" in r for r in wild_rules)
        assert any("bsize:" in r for r in wild_rules)
