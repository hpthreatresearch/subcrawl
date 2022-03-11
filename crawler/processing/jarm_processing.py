# © Copyright 2021 HP Development Company, L.P.
from urllib.parse import urlparse
from jarm.scanner.scanner import Scanner
from .default_processing import DefaultProcessing
import requests


class JARMProcessing(DefaultProcessing):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def process(self, url, resp):
        jarm_scan = {}
        try:
            domain = urlparse(url).netloc
            res = requests.get("https://" + domain) # Leads on purpose to an exception if connection is refused
            result = Scanner.scan(domain, 443)
            jarm_scan["fingerprint"] = result[0]
            jarm_scan["domain"] = result[1]
            jarm_scan["port"] = result[2]
        except Exception:
            pass
        return jarm_scan
