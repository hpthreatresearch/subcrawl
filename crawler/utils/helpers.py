# © Copyright 2021 HP Development Company, L.P.
import hashlib
import re
import sys

# Source: https://codereview.stackexchange.com/questions/19663/http-url-validating
valid_url = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


class SubCrawlHelpers:

    def get_sha256(data):
        hash_object = hashlib.sha256(data)
        return hash_object.hexdigest()

    def save_content(file_name, data):
        with open(file_name, "wb") as file:
            file.write(data)

    def make_safe_http(url):
        return url.replace('http', 'hxxp')

    def is_valid_url(url):
        if valid_url.match(url):
            return True
        else:
            return False

    def get_config(cfg, collection, key):
        try:
            return cfg[collection][key]
        except Exception as e:
            sys.exit("[ENGINE] Error loading configuration: "
                     + collection + " : " + key)
