from urllib.request import urlopen


def fetch_url():
    url = input("Enter URL: ")
    return urlopen(url)
