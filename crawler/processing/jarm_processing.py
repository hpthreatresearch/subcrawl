# © Copyright 2021 HP Development Company, L.P.
from urllib.parse import urlparse

from jarm.scanner.scanner import Scanner

from .default_processing import DefaultProcessing


class JARMProcessing(DefaultProcessing):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def process(self, url, resp):
        jarm_scan = {}
        domain = urlparse(url).netloc
        result = Scanner.scan(domain, 443)
        jarm_scan["fingerprint"] = result[0]
        jarm_scan["domain"] = result[1]
        jarm_scan["port"] = result[2]
        return jarm_scan
