from pathlib import Path

CONFIG_FILE = Path("config.json")


def read_config():
    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        return file.read()


def read_static_file():
    with open("README.md", "r", encoding="utf-8") as file:
        return file.read()
