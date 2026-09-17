import os
import logging
from src.sid_manager import SidManager
from src.fetcher import Fetcher
from src.generator import RuleGenerator
from src.providers import ProviderRegistry
from src.models import CategoryConfig

class Orchestrator:
    def __init__(self, sid_manager: SidManager, fetcher: Fetcher, generator: RuleGenerator):
        self.sid_manager = sid_manager
        self.fetcher = fetcher
        self.generator = generator
        self.global_seen_domains = set()
        self.category_rules = {}

    def process_categories(self, categories: list[CategoryConfig]):
        for category in categories:
            logging.info(f"Processing category: {category.name} (severity: {category.severity})")
            self.category_rules[category.name] = []
            
            self._process_feeds(category)
            self._process_manual_domains(category)
            self._process_custom_signatures(category)

    def _process_feeds(self, category: CategoryConfig):
        for feed in category.feeds:
            provider = ProviderRegistry.get(feed.provider)
            if not provider:
                logging.error(f"Provider {feed.provider} not found in registry. Skipping.")
                continue

            for feed_resource in feed.keys:
                feed_results = provider.fetch_and_parse(feed_resource, self.fetcher)
                
                for entity_name, domains in feed_results.items():
                    new_domains = self._filter_new_domains(domains)
                    if new_domains:
                        rules = self.generator.process_domains(category.name, entity_name, new_domains, category.severity, category.priority)
                        self.category_rules[category.name].extend(rules)
                        logging.info(f"Added {len(rules)} rules for {entity_name} (from feed {feed_resource}) in category {category.name}")

    def _process_manual_domains(self, category: CategoryConfig):
        for manual_entry in category.manual_domains:
            new_domains = self._filter_new_domains(manual_entry.domains)
            if new_domains:
                rules = self.generator.process_domains(category.name, manual_entry.name, new_domains, category.severity, category.priority)
                self.category_rules[category.name].extend(rules)
                logging.info(f"Added {len(rules)} rules for {manual_entry.name} in {category.name}")

    def _process_custom_signatures(self, category: CategoryConfig):
        for signature in category.custom_signatures:
            sid_key = f"sig:{signature.name}"
            if sid_key not in self.global_seen_domains:
                try:
                    rule = self.generator.generate_custom_rule(category.name, signature, category.severity, category.priority)
                    self.category_rules[category.name].append(rule)
                    self.global_seen_domains.add(sid_key)
                    logging.info(f"Added custom rule: {signature.name} in category {category.name}")
                except Exception as e:
                    logging.error(f"Error processing custom signature {signature.name}: {e}")

    def _filter_new_domains(self, domains):
        new_domains = []
        for domain_entry in domains:
            if domain_entry.domain not in self.global_seen_domains:
                new_domains.append(domain_entry)
                self.global_seen_domains.add(domain_entry.domain)
        return new_domains

    def write_rules(self, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        all_rules_list = []
        total_rules = 0

        for cat_name, rules in self.category_rules.items():
            if not rules:
                continue
                
            filename = os.path.join(output_dir, f"shadow-{cat_name.lower().replace(' ', '_')}.rules")
            unique_sorted_rules = sorted(list(set(rules)))
            
            with open(filename, 'w') as f:
                for rule in unique_sorted_rules:
                    f.write(rule + '\n')
            
            logging.info(f"Wrote {len(unique_sorted_rules)} rules to {filename}")
            total_rules += len(unique_sorted_rules)
            all_rules_list.extend(unique_sorted_rules)

        if all_rules_list:
            combined_rules = sorted(list(set(all_rules_list)))
            combined_filename = os.path.join(output_dir, "all_shadow_rules.rules")
            with open(combined_filename, 'w') as f:
                for rule in combined_rules:
                    f.write(rule + '\n')
            logging.info(f"Wrote {len(combined_rules)} combined rules to {combined_filename}")

        return total_rules
