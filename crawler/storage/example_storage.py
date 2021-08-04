# © Copyright 2021 HP Development Company, L.P.
import json
import pprint
from re import subn

from utils import SubCrawlColors
from .default_storage import DefaultStorage


class ExampleStorage(DefaultStorage):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def load_scraped_domains(self):
        return []

    def store_result(self, result_data):
        pass
