# © Copyright 2021 HP Development Company, L.P.
import csv
import io
import logging
from io import StringIO
from urllib.parse import urlparse

import requests
from pymisp import ExpandedPyMISP, MISPAttribute, MISPEvent, MISPObject
from utils import SubCrawlColors, SubCrawlHelpers
from .default_storage import DefaultStorage


class MISPStorage(DefaultStorage):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        logging.getLogger("pymisp").setLevel(logging.CRITICAL)
        self.cfg = config
        self.logger = logger

    def load_scraped_domains(self):
        misp = ExpandedPyMISP(SubCrawlHelpers.get_config(self.cfg, "misp", "misp_url"), SubCrawlHelpers.get_config(self.cfg, "misp", "misp_api_key"), False)

        domains = set()
        domain_event = None
        if SubCrawlHelpers.get_config(self.cfg, "misp", "domain_event") != 0:
            domain_event = misp.get_event(SubCrawlHelpers.get_config(self.cfg, "misp", "domain_event"), pythonify=True)
            for att in domain_event.attributes:
                if att.type == "domain":
                    domains.add(att.value)
        else:
            self.logger.warning('[MISP] No domain MISP event configured')

        return domains

    def store_result(self, result_data):
        misp = ExpandedPyMISP(SubCrawlHelpers.get_config(self.cfg, "misp", "misp_url"), SubCrawlHelpers.get_config(self.cfg, "misp", "misp_api_key"), False)

        domain_event = None
        if SubCrawlHelpers.get_config(self.cfg, "misp", "domain_event") != 0:
            domain_event = misp.get_event(SubCrawlHelpers.get_config(self.cfg, "misp", "domain_event"), pythonify=True)

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

                jarm_added = False
                event_data = misp.search_index(eventinfo=domain, pythonify=True)
                if len(event_data) > 0:
                    event = event_data[0]
                else:
                    event = MISPEvent()
                    event.distribution = 1
                    event.threat_level_id = 4
                    event.analysis = 1
                    event.info = domain

                    for tag in tags:
                        event.add_tag(tag)
                    event.add_tag("tlp:green")

                    event = misp.add_event(event, pythonify=True)

                server_created = False
                scripttech_created = False

                attribute = MISPAttribute()
                attribute.type = "domain"
                attribute.value = domain
                misp.add_attribute(event, attribute)
                if domain_event:
                    dom_attribute = MISPAttribute()  # Not beautiful but new attribute must be generated due to the UUID
                    dom_attribute.type = "domain"
                    dom_attribute.value = domain
                    misp.add_attribute(domain_event, dom_attribute)

                for url_content in result_data[domain]:

                    obj = MISPObject(name='opendir-url', strict=True, misp_objects_path_custom='./misp-objects')
                    obj.add_attribute('url', value=str(url_content["url"]))
                    obj.add_attribute('sha256', value=str(url_content["sha256"]))

                    # obj.add_attribute("content", value=content_data[:20], data=content_data, expand='store_true')

                    if "index of" in str(url_content["data"]["title"]).lower():
                        event.add_tag("opendir")
                        misp.update_event(event)

                    obj.add_attribute('title', value=str(url_content["data"]["title"]))
                    obj.add_attribute('status-code', value=url_content["data"]["resp"]["status_code"])

                    for header in url_content["data"]["resp"]["headers"]:
                        obj.add_attribute('header', comment=header, value=url_content["data"]["resp"]["headers"][header])

                    if not server_created:
                        if "Server" in url_content["data"]["resp"]["headers"]:
                            attribute = MISPAttribute()
                            attribute.type = "other"
                            attribute.comment = "Webserver"
                            attribute.value = url_content["data"]["resp"]["headers"]["Server"]
                            misp.add_attribute(event, attribute)
                            server_created = True

                    if not scripttech_created:
                        if "X-Powered-By" in url_content["data"]["resp"]["headers"]:
                            attribute = MISPAttribute()
                            attribute.type = "other"
                            attribute.comment = "Scripting Technology"
                            attribute.value = url_content["data"]["resp"]["headers"]["X-Powered-By"]
                            misp.add_attribute(event, attribute)
                            scripttech_created = True

                    try:
                        for module in url_content["modules"]:
                            if len(url_content["modules"][module]) > 0:
                                if module == "JARMProcessing" and not jarm_added:
                                    jarm_obj = MISPObject(name='jarm', strict=True)
                                    jarm_obj.add_attribute("jarm", value=str(url_content["modules"][module]["fingerprint"]))
                                    misp.add_object(event, jarm_obj)
                                    jarm_added = True
                                elif module == "SDhashProcessing":
                                    obj.add_attribute('sdhash', value=str(url_content["modules"][module]["sdhash"]))
                                elif module == "TLSHProcessing":
                                    obj.add_attribute('tlsh', value=str(url_content["modules"][module]["tlsh"]))
                                elif module == "YARAProcessing":
                                    for rule in url_content["modules"][module]["rules"]:
                                        obj.add_attribute('yara', value=str(rule))

                    except Exception as e:
                        self.logger.error('[MISP] ' + str(e))

                    misp.add_object(event, obj)

                misp.publish(event)
                self.logger.info("[MISP] Event created: " + domain)

        if domain_event:
            misp.publish(domain_event)
