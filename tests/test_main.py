import os
import yaml
import pytest
from unittest.mock import MagicMock
from src.sid_manager import SidManager
from src.generator import RuleGenerator
from src.models import CategoryConfig, DomainEntry
from src.orchestrator import Orchestrator
from src.providers import ProviderRegistry, FeedProvider
from main import load_config

# A simple mock provider for testing
class MockProvider(FeedProvider):
    def __init__(self, data):
        self.data = data

    def fetch_and_parse(self, resource_id, fetcher):
        return self.data.get(resource_id, {})

@pytest.fixture
def setup_orchestrator():
    sid_manager = SidManager(start_sid=8000)
    fetcher = MagicMock()
    generator = RuleGenerator(sid_manager)
    orchestrator = Orchestrator(sid_manager, fetcher, generator)
    return orchestrator, fetcher

class TestOrchestratorIntegration:
    def test_mixed_feeds_and_manual_domains(self, setup_orchestrator):
        orchestrator, fetcher = setup_orchestrator

        # Register a test provider
        test_provider = MockProvider({
            "feed1": {
                "EntityFromFeed": [DomainEntry("feed-domain.com", is_full=False)]
            }
        })
        ProviderRegistry.register("test_provider", test_provider)

        config = [
            CategoryConfig.from_dict({
                "name": "MixedCat",
                "feeds": {"test_provider": ["feed1"]},
                "manual_domains": [
                    {"name": "ManualEnt", "domains": ["manual-domain.com"]}
                ]
            })
        ]

        orchestrator.process_categories(config)
        rules = orchestrator.category_rules["MixedCat"]

        # 2 non-full domains * 2 rules each = 4
        assert len(rules) == 4
        assert any("feed-domain.com" in r for r in rules)
        assert any("manual-domain.com" in r for r in rules)
        assert any("EntityFromFeed" in r for r in rules)
        assert any("ManualEnt" in r for r in rules)

    def test_deduplication_between_feed_and_manual_domain(self, setup_orchestrator):
        orchestrator, fetcher = setup_orchestrator

        test_provider = MockProvider({
            "feed1": {
                "EntityFromFeed": [DomainEntry("duplicate.com", is_full=False)]
            }
        })
        ProviderRegistry.register("test_provider", test_provider)

        config = [
            CategoryConfig.from_dict({
                "name": "DupCat",
                "feeds": {"test_provider": ["feed1"]},
                "manual_domains": [
                    {"name": "ManualEnt", "domains": ["duplicate.com"]}
                ]
            })
        ]

        orchestrator.process_categories(config)
        rules = orchestrator.category_rules["DupCat"]

        # Feed is processed before manual domains within a category
        # 1 deduplicated non-full domain * 2 rules = 2
        assert len(rules) == 2
        assert all("EntityFromFeed" in r for r in rules)
        assert all("ManualEnt" not in r for r in rules)

    def test_multiple_providers(self, setup_orchestrator):
        orchestrator, _ = setup_orchestrator

        ProviderRegistry.register("p1", MockProvider({"f1": {"E1": [DomainEntry("d1.com")]}}))
        ProviderRegistry.register("p2", MockProvider({"f2": {"E2": [DomainEntry("d2.com")]}}))

        config = [
            CategoryConfig.from_dict({
                "name": "MultiProv",
                "feeds": {
                    "p1": ["f1"],
                    "p2": ["f2"]
                }
            })
        ]

        orchestrator.process_categories(config)
        rules = orchestrator.category_rules["MultiProv"]
        # 2 non-full domains * 2 rules each = 4
        assert len(rules) == 4
        assert any("d1.com" in r for r in rules)
        assert any("d2.com" in r for r in rules)

class TestLoadConfig:
    def test_legacy_list_format(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump([
            {"name": "CatA", "severity": 4, "feeds": {"v2fly": ["foo"]}},
            {"name": "CatB", "severity": 3, "feeds": {"v2fly": ["bar"]}},
        ]))
        result = load_config(str(config_file))
        assert len(result) == 2
        assert isinstance(result[0], CategoryConfig)

    def test_manifest_includes_children(self, tmp_path):
        cat_dir = tmp_path / "feeds"
        cat_dir.mkdir()
        (cat_dir / "alpha.yaml").write_text(yaml.dump({"name": "Alpha", "severity": 4}))
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(yaml.dump({"include": ["feeds/alpha.yaml"]}))

        result = load_config(str(manifest))
        assert len(result) == 1
        assert result[0].name == "Alpha"

    def test_real_manifest_loads_successfully(self):
        result = load_config("config/manifest.yaml")
        assert len(result) > 0
        for cat in result:
            assert isinstance(cat, CategoryConfig)
