import yaml
import logging
import argparse
import os
from src.sid_manager import SidManager
from src.fetcher import Fetcher
from src.generator import RuleGenerator
from src.models import CategoryConfig
from src.orchestrator import Orchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def load_config(path):
    """Loads configuration from a manifest file or a single category file."""
    with open(path, 'r') as f:
        data = yaml.safe_load(f)

    if not data:
        return []

    # Manifest mode: file contains an "include" list pointing to child files
    if isinstance(data, dict) and 'include' in data:
        base_dir = os.path.dirname(path)
        categories = []
        for child_path in data['include']:
            full_path = os.path.join(base_dir, child_path)
            with open(full_path, 'r') as f:
                entry = yaml.safe_load(f)
                if entry:
                    categories.append(CategoryConfig.from_dict(entry))
        return categories

    # Legacy mode: single file with a list of categories or a single category
    if isinstance(data, list):
        return [CategoryConfig.from_dict(e) for e in data]
    return [CategoryConfig.from_dict(data)]

def main():
    parser = argparse.ArgumentParser(description="Generate Suricata rules from domain lists.")
    parser.add_argument("--config", default="config/manifest.yaml", help="Path to configuration file")
    parser.add_argument("--output", default="rules", help="Directory for output rules")
    args = parser.parse_args()

    try:
        categories = load_config(args.config)
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        return

    # Initialize components
    sid_manager = SidManager()
    fetcher = Fetcher()
    generator = RuleGenerator(sid_manager)
    orchestrator = Orchestrator(sid_manager, fetcher, generator)

    # Process and generate rules
    orchestrator.process_categories(categories)
    total_rules = orchestrator.write_rules(args.output)

    logging.info(f"Completed. Total unique rules generated: {total_rules}")

if __name__ == "__main__":
    main()
