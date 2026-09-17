from abc import ABC, abstractmethod
import logging
from src.parser import DomainParser
from src.models import DomainEntry, VALID_PROVIDERS

class FeedProvider(ABC):
    """
    To add a new provider:
    1. Create a class that inherits from FeedProvider.
    2. Implement the fetch_and_parse method.
    3. Register the provider at the end of this file: ProviderRegistry.register("name", MyProvider())
    """
    @abstractmethod
    def fetch_and_parse(self, resource_id, fetcher):
        """
        Fetches the content for a given resource_id and parses it into DomainEntry objects.
        Returns a dictionary mapping entity names (e.g. "Google") to lists of DomainEntry objects.
        """
        pass

class V2FlyProvider(FeedProvider):
    def __init__(self, base_url="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data"):
        self.base_url = base_url

    def fetch_and_parse(self, resource_id, fetcher):
        results = {}
        visited_resources = set()
        self._resolve_recursive(resource_id, fetcher, visited_resources, results)
        return results

    def _resolve_recursive(self, current_resource, fetcher, visited_resources, results):
        if current_resource in visited_resources:
            return

        visited_resources.add(current_resource)
        url = f"{self.base_url}/{current_resource}"

        content = fetcher._fetch_url(url)
        if not content:
            return

        domains, include_keys = DomainParser.extract_domains(content)
        
        entity_name = " ".join([w.capitalize() for w in current_resource.replace("!cn", "non-cn").split("-")])
        if domains:
            if entity_name not in results:
                results[entity_name] = []
            results[entity_name].extend(domains)

        for sub_resource in include_keys:
            self._resolve_recursive(sub_resource, fetcher, visited_resources, results)

class ProviderRegistry:
    _providers = {}

    @classmethod
    def register(cls, name, provider_instance):
        cls._providers[name] = provider_instance
        VALID_PROVIDERS.add(name)

    @classmethod
    def get(cls, name):
        return cls._providers.get(name)

    @classmethod
    def list_providers(cls):
        return list(cls._providers.keys())

# Register default providers
ProviderRegistry.register("v2fly", V2FlyProvider())
