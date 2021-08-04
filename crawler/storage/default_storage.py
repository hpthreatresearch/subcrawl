# © Copyright 2021 HP Development Company, L.P.

class DefaultStorage:

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def load_scraped_domains(self):
        return []

    def store_result(self, result_data):
        return True
