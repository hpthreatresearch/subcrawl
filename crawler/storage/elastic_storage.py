# © Copyright 2021 HP Development Company, L.P.
import json
import pprint
import warnings
from urllib.parse import urlparse
from re import subn
from elasticsearch import Elasticsearch, helpers

from utils import SubCrawlColors, SubCrawlHelpers
from .default_storage import DefaultStorage


class ElasticStorage(DefaultStorage):

    cfg = None
    logger = None
    es = None
    index = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger
        self.index = SubCrawlHelpers.get_config(self.cfg, 'elasticsearch', 'index')

        try:
            self.es = Elasticsearch([{'host': SubCrawlHelpers.get_config(self.cfg, 'elasticsearch', 'host'),
                                    'port': SubCrawlHelpers.get_config(self.cfg, 'elasticsearch', 'port'),
                                    'index': self.index}])
            self.es.ping()

            if self.es.indices.exists(self.index) == False:
                self.logger.debug('[ELASTIC] Index did not exist, creating: ' + self.index)
                self.es.indices.create(index=self.index)
            
        except Exception as e:
            self.logger.error('[ELASTIC] Problem connecting to Elastic: ' + str(e))
            raise e

    def load_scraped_domains(self):
        return []

    def store_result(self, result_data):
        data = {}
        doc_list = []

        try:
            for domain in result_data:
                for url_content in result_data[domain]:
                    parsed_url = urlparse(url_content['url'])

                    data = {
                        'url': url_content['url'],
                        'scheme': parsed_url.scheme,
                        'netloc': parsed_url.netloc,
                        'path': parsed_url.path,
                        'params': parsed_url.params,
                        'query': parsed_url.query,
                        'fragment': parsed_url.fragment,
                        'scraped_on': url_content['scraped_on'],
                        'sha256': url_content['sha256'],                        
                        'content_magic': url_content['content_type'],
                        'signature': url_content['signature'],
                        'title': url_content['data']['title'],
                        'response_content': url_content['data']['text'],
                        'status_code': url_content['data']['resp']['status_code'],
                    }

                    for header in url_content['data']['resp']['headers']:
                        data[header] = url_content['data']['resp']['headers'][header]

                    for module in url_content["modules"]:
                        if len(url_content["modules"][module]) > 0:
                            if module == "YARAProcessing":
                                data["yara_results"] = url_content["modules"][module]["matches"]
                    doc_list.append(data)
   
            helpers.bulk(
                self.es,
                doc_list,
                index=self.index
            )

            self.logger.info('[ELASTIC] added ' + str(len(doc_list)) + ' items')

        except Exception as e:
            self.logger.error('[ELASTIC] Problem adding data: ' + str(e))
