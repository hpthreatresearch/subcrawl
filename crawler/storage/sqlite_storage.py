# © Copyright 2021 HP Development Company, L.P.
import csv
import io
import logging
from io import StringIO
from urllib.parse import urlparse

import requests
from utils import Domain, DomainTag, Extension, Tag, Url, db, fn
from utils import SubCrawlColors, SubCrawlHelpers
from .default_storage import DefaultStorage


class SqliteStorage(DefaultStorage):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def load_scraped_domains(self):
        domains = Domain.select()
        return domains

    def store_result(self, result_data):
        # Load URLHaus tags
        url_info = dict()
        r = requests.get(SubCrawlHelpers.get_config(self.cfg, "crawler", "urlhaus_api"), allow_redirects=True)
        csv_data = io.StringIO(r.content.decode("utf-8"))
        counter = 0
        while counter < 8:
            next(csv_data)
            counter += 1

        csv_reader = csv.DictReader(csv_data)
        for row in csv_reader:
            domain = urlparse(row["url"]).netloc
            if domain not in url_info:
                url_info[domain] = set()
            url_info[domain].update(row["tags"].lower().split(","))

        for domain in result_data:
            tags = []
            if domain in url_info:
                tags = url_info[domain]

            if len(result_data[domain]) > 0:
                domains = Domain.select().where(Domain.name == domain)

                if len(domains) > 0:
                    ref_domain = domains[0]
                else:
                    ref_domain = Domain(name=domain)
                    ref_domain.save()

                    for tag in tags:
                        db_tag = Tag.select().where(Tag.tag == tag)
                        if len(db_tag) == 0:
                            db_tag = Tag(tag=tag)
                            db_tag.save()
                        dt = DomainTag(domain=ref_domain, tag=db_tag)
                        dt.save()

                for url_content in result_data[domain]:

                    url = Url(domain=ref_domain, url=str(url_content["url"]), status_code=url_content["data"]["resp"]["status_code"], title=str(url_content["data"]["title"]), sha256=str(url_content["sha256"]))
                    url.save()

                    if "index of" in str(url_content["data"]["title"]).lower():
                        db_tag = Tag.select().where(Tag.tag == "opendir")
                        if len(db_tag) == 0:
                            db_tag = Tag(tag="opendir")
                            db_tag.save()

                        dt = DomainTag.select().where(DomainTag.domain == ref_domain, DomainTag.tag == db_tag)
                        if len(dt) == 0:
                            dt = DomainTag(domain=ref_domain, tag=db_tag)
                            dt.save()

                    for header in url_content["data"]["resp"]["headers"]:
                        ext = Extension(key=str(header).lower(), value=url_content["data"]["resp"]["headers"][header], url=url)
                        ext.save()

                    try:
                        for module in url_content["modules"]:
                            if len(url_content["modules"][module]) > 0:
                                if module == "JARMProcessing":
                                    ext = Extension(key="jarm", value=str(url_content["modules"][module]["fingerprint"]), url=url)
                                    ext.save()

                                elif module == "SDhashProcessing":
                                    ext = Extension(key="sdhash", value=str(url_content["modules"][module]["sdhash"]), url=url)
                                    ext.save()

                                elif module == "TLSHProcessing":
                                    ext = Extension(key="tlsh", value=str(url_content["modules"][module]["tlsh"]), url=url)
                                    ext.save()

                                elif module == "YARAProcessing":
                                    for rule in url_content["modules"][module]["rules"]:
                                        ext = Extension(key="yara", value=str(rule), url=url)
                                        ext.save()

                    except Exception as e:
                        self.logger.error('[SQLite] ' + str(e))

                self.logger.info("[SQLite] Scan results stored: " + domain)
