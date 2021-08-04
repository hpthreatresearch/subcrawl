# © Copyright 2021 HP Development Company, L.P.
from .default_processing import DefaultProcessing


class ExampleProcessing(DefaultProcessing):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def process(self, url, resp):
        pass
