from urllib.request import urlopen


SAFE_URL = "https://example.com"


def fetch_safe_url():
    return urlopen(SAFE_URL)
