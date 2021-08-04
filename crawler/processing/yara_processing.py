# © Copyright 2021 HP Development Company, L.P.
import hashlib

import yara
from utils import SubCrawlColors, SubCrawlHelpers
from .default_processing import DefaultProcessing


class YARAProcessing(DefaultProcessing):

    cfg = None
    rules = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def process(self, url, content):
        if not self.rules:
            self.rules = yara.compile(filepath=SubCrawlHelpers.get_config(
                                       self.cfg, "crawler", "yara_rules"))

        yara_matches = {}
        http_resp = content.decode("latin-1")

        matches = self.rules.match(data=http_resp)
        if len(matches) > 0:
            self.logger.info(SubCrawlColors.CYAN + "[YARA] Matches - " +
                             ' '.join(map(str, matches)) +
                             " (" + url + " )" + SubCrawlColors.RESET)
            yara_matches["url"] = url
            yara_matches["hash"] = SubCrawlHelpers.get_sha256(
                                    http_resp.encode('utf-8'))
            for match in matches:
                yara_matches.setdefault("matches", []).append(str(match))

        return yara_matches
