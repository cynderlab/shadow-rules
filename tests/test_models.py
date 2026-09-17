import pytest
from src.models import CategoryConfig, DomainEntry, FeedConfig, ManualDomainConfig


class TestCategoryConfigFromDict:
    def test_minimal_valid(self):
        cat = CategoryConfig.from_dict({"name": "Test"})
        assert cat.name == "Test"
        assert cat.severity == 3  # default
        assert cat.priority == 3  # default
        assert cat.feeds == []
        assert cat.manual_domains == []

    def test_with_priority(self):
        cat = CategoryConfig.from_dict({"name": "Test", "priority": 2})
        assert cat.priority == 2

    def test_with_feeds(self):
        cat = CategoryConfig.from_dict({
            "name": "GenAI",
            "severity": 3,
            "feeds": {"v2fly": ["category-ai-!cn", "openai"]},
        })
        assert cat.name == "GenAI"
        assert cat.severity == 3
        assert len(cat.feeds) == 1
        assert cat.feeds[0].provider == "v2fly"
        assert cat.feeds[0].keys == ["category-ai-!cn", "openai"]

    def test_with_manual_domains(self):
        cat = CategoryConfig.from_dict({
            "name": "Remote",
            "manual_domains": [
                {"name": "TeamViewer", "domains": ["teamviewer.com", "full:exact.tv.com"]},
            ],
        })
        assert len(cat.manual_domains) == 1
        svc = cat.manual_domains[0]
        assert svc.name == "TeamViewer"
        assert len(svc.domains) == 2
        assert svc.domains[0] == DomainEntry("teamviewer.com", is_full=False)
        assert svc.domains[1] == DomainEntry("exact.tv.com", is_full=True)

    def test_full_prefix_parsed_in_manual_domains(self):
        cat = CategoryConfig.from_dict({
            "name": "Test",
            "manual_domains": [
                {"name": "Svc", "domains": ["full:remotedesktop.google.com"]},
            ],
        })
        entry = cat.manual_domains[0].domains[0]
        assert entry.domain == "remotedesktop.google.com"
        assert entry.is_full is True
        assert "full:" not in entry.domain

    def test_custom_signatures_with_overrides(self):
        cat = CategoryConfig.from_dict({
            "name": "Test",
            "severity": 2,
            "priority": 2,
            "custom_signatures": [
                {
                    "name": "Overridden",
                    "severity": 1,
                    "priority": 1,
                    "options": "content:\"foo\";"
                },
                {
                    "name": "Defaulted",
                    "options": "content:\"bar\";"
                }
            ]
        })
        assert len(cat.custom_signatures) == 2
        assert cat.custom_signatures[0].severity == 1
        assert cat.custom_signatures[0].priority == 1
        assert cat.custom_signatures[1].severity is None
        assert cat.custom_signatures[1].priority is None


class TestCategoryConfigValidation:
    def test_missing_name_raises(self):
        with pytest.raises(ValueError, match="name"):
            CategoryConfig.from_dict({"severity": 4})

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError, match="severity"):
            CategoryConfig.from_dict({"name": "Test", "severity": 5})

    def test_invalid_priority_raises(self):
        with pytest.raises(ValueError, match="priority"):
            CategoryConfig.from_dict({"name": "Test", "priority": 0})

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="unknown feed provider"):
            CategoryConfig.from_dict({
                "name": "Test",
                "feeds": {"bad_provider": ["foo"]},
            })

    def test_unknown_field_raises(self):
        with pytest.raises(ValueError, match="Unknown fields"):
            CategoryConfig.from_dict({
                "name": "Test",
                "typo_field": "oops",
            })

    def test_source_typo_caught(self):
        """Common mistake: 'source' instead of 'feeds'."""
        with pytest.raises(ValueError, match="Unknown fields"):
            CategoryConfig.from_dict({
                "name": "Test",
                "source": ["category-ai"],
            })

    def test_manual_typo_caught(self):
        """Common mistake: 'manual' instead of 'manual_domains'."""
        with pytest.raises(ValueError, match="Unknown fields"):
            CategoryConfig.from_dict({
                "name": "Test",
                "manual": [{"name": "Svc", "domains": ["a.com"]}],
            })

    def test_manual_domain_without_name_raises(self):
        with pytest.raises(ValueError, match="must have a 'name'"):
            CategoryConfig.from_dict({
                "name": "Test",
                "manual_domains": [{"domains": ["a.com"]}],
            })

    def test_not_a_dict_raises(self):
        with pytest.raises(ValueError, match="must be a dict"):
            CategoryConfig.from_dict("not a dict")

    def test_feed_keys_not_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            CategoryConfig.from_dict({
                "name": "Test",
                "feeds": {"v2fly": "not-a-list"},
            })

