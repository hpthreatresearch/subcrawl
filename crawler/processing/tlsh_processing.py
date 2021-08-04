# © Copyright 2021 HP Development Company, L.P.
from .default_processing import DefaultProcessing
import tlsh


class TLSHProcessing(DefaultProcessing):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def process(self, url, content):
        tlsh_result = {}
        if len(content) < 50:
            return {}

        try:
            tlsh_result["tlsh"] = tlsh.hash(content)
            tlsh_result["url"] = url
        except Exception as e:
            self.logger.ERROR('[TLSH] ' + str(e))
            pass
        return tlsh_result
