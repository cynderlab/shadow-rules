from src.parser import DomainParser
from src.models import DomainEntry


class TestCleanDomain:
    def test_normal_domain(self):
        assert DomainParser.clean_domain("example.com") == "example.com"

    def test_empty_line(self):
        assert DomainParser.clean_domain("") is None

    def test_whitespace_only(self):
        assert DomainParser.clean_domain("   ") is None

    def test_comment_line(self):
        assert DomainParser.clean_domain("# this is a comment") is None

    def test_full_prefix(self):
        assert DomainParser.clean_domain("full:exact.example.com") == "exact.example.com"

    def test_regexp_prefix(self):
        assert DomainParser.clean_domain("regexp:.*\\.example\\.com") is None

    def test_include_prefix(self):
        assert DomainParser.clean_domain("include:other-file") is None

    def test_at_suffix_removed(self):
        assert DomainParser.clean_domain("example.com@ads") == "example.com"

    def test_inline_comment_removed(self):
        assert DomainParser.clean_domain("example.com # some note") == "example.com"


class TestExtractDomains:
    def test_simple_domains(self):
        content = "example.com\ntest.org\n"
        domains, includes = DomainParser.extract_domains(content)
        assert domains == [DomainEntry("example.com"), DomainEntry("test.org")]
        assert includes == []

    def test_full_prefix_marks_is_full(self):
        content = "full:exact.example.com\n"
        domains, includes = DomainParser.extract_domains(content)
        assert domains == [DomainEntry("exact.example.com", is_full=True)]

    def test_full_prefix_strips_domain_only(self):
        """full: prefix must be stripped, leaving just the domain."""
        content = "full:remotedesktop.google.com\n"
        domains, _ = DomainParser.extract_domains(content)
        entry = domains[0]
        assert entry.domain == "remotedesktop.google.com"
        assert "full:" not in entry.domain
        assert entry.is_full is True

    def test_non_full_domain_is_not_full(self):
        content = "google.com\n"
        domains, _ = DomainParser.extract_domains(content)
        assert domains[0] == DomainEntry("google.com", is_full=False)

    def test_full_and_non_full_coexist(self):
        content = "full:exact.com\nwildcard.com\n"
        domains, _ = DomainParser.extract_domains(content)
        by_domain = {d.domain: d.is_full for d in domains}
        assert by_domain["exact.com"] is True
        assert by_domain["wildcard.com"] is False

    def test_full_with_at_suffix(self):
        """full: combined with @attr — prefix stripped, suffix stripped, is_full kept."""
        content = "full:exact.com@cn\n"
        domains, _ = DomainParser.extract_domains(content)
        assert domains == [DomainEntry("exact.com", is_full=True)]

    def test_includes_extracted(self):
        content = "include:other-list\nexample.com\n"
        domains, includes = DomainParser.extract_domains(content)
        assert domains == [DomainEntry("example.com")]
        assert includes == ["other-list"]

    def test_regexp_skipped(self):
        content = "regexp:.*\\.example\\.com\nexample.com\n"
        domains, includes = DomainParser.extract_domains(content)
        assert domains == [DomainEntry("example.com")]

    def test_comments_and_blanks_skipped(self):
        content = "# header\n\nexample.com\n# footer\n"
        domains, includes = DomainParser.extract_domains(content)
        assert domains == [DomainEntry("example.com")]

    def test_at_suffix_in_include(self):
        content = "include:other-list@cn\n"
        domains, includes = DomainParser.extract_domains(content)
        assert domains == []
        assert includes == ["other-list"]

    def test_sorted_output(self):
        content = "zebra.com\nalpha.com\nmid.com\n"
        domains, includes = DomainParser.extract_domains(content)
        assert [d.domain for d in domains] == ["alpha.com", "mid.com", "zebra.com"]

    def test_multiline_mixed(self):
        content = (
            "# comment\n"
            "include:inc-a\n"
            "full:exact.com\n"
            "normal.com\n"
            "regexp:^test\n"
            "include:inc-b\n"
            "other.com@ads\n"
        )
        domains, includes = DomainParser.extract_domains(content)
        assert DomainEntry("exact.com", is_full=True) in domains
        assert DomainEntry("normal.com") in domains
        assert DomainEntry("other.com") in domains
        assert len(domains) == 3
        assert set(includes) == {"inc-a", "inc-b"}
