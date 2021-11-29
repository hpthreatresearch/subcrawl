# © Copyright 2021 HP Development Company, L.P.
import os
import zipfile
import io
from datetime import datetime
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
    archive_location = None
    archive_content = False

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger
        self.archive_location = SubCrawlHelpers.get_config(self.cfg,'elasticsearch', 'archive_log_location')
        self.archive_content = SubCrawlHelpers.get_config(self.cfg, 'elasticsearch', 'archive_response_content')
        self.index = SubCrawlHelpers.get_config(self.cfg, 'elasticsearch', 'index')

        try:
            self.es = Elasticsearch([{'host': SubCrawlHelpers.get_config(self.cfg, 'elasticsearch', 'host'),
                                    'port': SubCrawlHelpers.get_config(self.cfg, 'elasticsearch', 'port'),
                                    'index': self.index}])
            self.es.ping()

            if self.es.indices.exists(self.index) == False:
                self.logger.debug('[ELASTIC] Index did not exist, creating: ' + self.index)
                self.es.indices.create(index=self.index)

            if self.archive_content:
                if not os.path.isdir(self.archive_location):
                    os.mkdir(self.archive_location)
                    self.logger.debug('[ELASTIC] Response content being saved, log created at: ' + self.archive_location)
            
        except Exception as e:
            self.logger.error('[ELASTIC] Problem connecting to Elastic: ' + str(e))
            raise e

    def load_scraped_domains(self):
        return []

    def normalize_field_name(self, field_name):
        return field_name.replace(' ','-').replace('-','_').lower()

    def store_content(self, content_buffer, file_name):

        try:
            tmp_buffer = io.BytesIO()

            with zipfile.ZipFile(tmp_buffer, mode='w',compression=zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr('http.response.payload', str.encode(content_buffer,'utf-8'))

            with open(self.archive_location + file_name,'wb') as tmp_zip:
                tmp_zip.write(tmp_buffer.getvalue())

        except Exception as ex:
            self.logger.error('[ELASTIC] Problem adding data: ' + str(ex))


    def store_result(self, result_data):
        data = {}
        doc_list = []

        try:
            for domain in result_data:
                for url_content in result_data[domain]:
                    parsed_url = urlparse(url_content['url'])

                    data = {
                        'http.request.url': url_content['url'],
                        'http.request.scheme': parsed_url.scheme,
                        'http.request.netloc': parsed_url.netloc,
                        'http.request.path': parsed_url.path,
                        'http.request.params': parsed_url.params,
                        'http.request.query': parsed_url.query,
                        'http.request.fragment': parsed_url.fragment,
                        'crawled_on': url_content['scraped_on'],
                        'http.response.body.content.sha256': url_content['sha256'],                        
                        'http.response.body.content_magic': url_content['content_type'],
                        'http.signature': url_content['signature'],
                        'http.response.title': url_content['data']['title'],
                        'http.response.status_code': url_content['data']['resp']['status_code'],
                    }

                    for header in url_content['data']['resp']['headers']:
                        data['http.response.header.' + self.normalize_field_name(header)] = url_content['data']['resp']['headers'][header]

                    for module in url_content['modules']:
                        if len(url_content['modules'][module]) > 0:
                            if module == 'YARAProcessing':
                                data['yara_results'] = url_content['modules'][module]['matches']

                    if self.archive_content:
                        tmp_dt = datetime.strptime(url_content['scraped_on'][:-7], '%Y-%m-%dT%H:%M:%S')
                        self.store_content(url_content['data']['text'],str(int(tmp_dt.timestamp())) + '_' + url_content['sha256'])

                    doc_list.append(data)

            helpers.bulk(
                self.es,
                doc_list,
                index=self.index
            )

            self.logger.info('[ELASTIC] added ' + str(len(doc_list)) + ' items')

        except Exception as e:
            self.logger.error('[ELASTIC] Problem adding data: ' + str(e))
