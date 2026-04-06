import requests


def bootlin_ident(project: str, version: str, family: str, symbol: str) -> dict:
    url = f"https://elixir.bootlin.com/api/ident/{project}/{symbol}"
    params = {
        "version": version,
        "family": family,
    }
    r = requests.get(url, params=params, timeout=30)
    r.raise_for_status()
    return r.json()
