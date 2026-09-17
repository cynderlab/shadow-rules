import requests
import concurrent.futures
import logging

class Fetcher:
    def __init__(self, max_workers=5):
        self.session = requests.Session()
        self.max_workers = max_workers
        self.cache = {}
        # Basic header to look polite
        self.session.headers.update({
            'User-Agent': 'CYNDERLAB-shadows-rule-generator/1.0'
        })

    def _fetch_url(self, url):
        if url in self.cache:
            return self.cache[url]

        # Convert github.com to raw if needed
        if "github.com" in url and "blob" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            
        try:
            logging.info(f"Downloading from {url}...")
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            self.cache[url] = response.text
            return response.text
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch {url}: {e}")
            return None

    def fetch_sources(self, sources):
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self._fetch_url, source['url']): source for source in sources}
            
            for future in concurrent.futures.as_completed(future_to_url):
                source = future_to_url[future]
                try:
                    content = future.result()
                    if content:
                        results[source['name']] = content
                except Exception as e:
                    logging.error(f"Error processing {source['name']}: {e}")
        return results
