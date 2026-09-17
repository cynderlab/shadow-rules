from src.sid_manager import SidManager
from src.generator import RuleGenerator
from src.models import CustomSignatureConfig, DomainEntry


def make_generator():
    sid_mgr = SidManager(start_sid=9000)
    return RuleGenerator(sid_mgr), sid_mgr


class TestCustomPriorityAndSeverity:
    def test_custom_rule_inherits_category_defaults(self):
        gen, _ = make_generator()
        sig = CustomSignatureConfig(name="TestSig", options='content:"foo";')
        rule = gen.generate_custom_rule("TestCat", sig, severity=2, priority=2)
        assert "signature_severity Major" in rule
        assert "priority:2;" in rule

    def test_custom_rule_overrides_severity(self):
        gen, _ = make_generator()
        sig = CustomSignatureConfig(name="TestSig", options='content:"foo";', severity=1)
        rule = gen.generate_custom_rule("TestCat", sig, severity=3, priority=3)
        assert "signature_severity Critical" in rule
        assert "priority:3;" in rule

    def test_custom_rule_overrides_priority(self):
        gen, _ = make_generator()
        sig = CustomSignatureConfig(name="TestSig", options='content:"foo";', priority=1)
        rule = gen.generate_custom_rule("TestCat", sig, severity=3, priority=3)
        assert "signature_severity Minor" in rule
        assert "priority:1;" in rule

    def test_custom_rule_overrides_both(self):
        gen, _ = make_generator()
        sig = CustomSignatureConfig(name="TestSig", options='content:"foo";', severity=1, priority=1)
        rule = gen.generate_custom_rule("TestCat", sig, severity=4, priority=4)
        assert "signature_severity Critical" in rule
        assert "priority:1;" in rule

    def test_domain_rule_uses_category_priority(self):
        gen, _ = make_generator()
        domain_entry = DomainEntry("example.com")
        rules = gen.generate_rules("TestCat", "TestSvc", domain_entry, severity=2, priority=2)
        for rule in rules:
            assert "signature_severity Major" in rule
            assert "priority:2;" in rule

    def test_process_domains_passes_priority(self):
        gen, _ = make_generator()
        domains = [DomainEntry("example.com")]
        rules = gen.process_domains("TestCat", "TestSvc", domains, severity=1, priority=1)
        for rule in rules:
            assert "signature_severity Critical" in rule
            assert "priority:1;" in rule
