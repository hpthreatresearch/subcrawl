# © Copyright 2021 HP Development Company, L.P.
import argparse
import base64
import datetime
import hashlib
import inspect
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from io import BytesIO
from multiprocessing import Pool, cpu_count
from urllib.parse import urljoin, urlparse

import magic
import requests
import yaml
from bs4 import BeautifulSoup
from mergedeep import Strategy, merge
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from processing import *
from storage import *
from utils import (SubCrawlBanner, SubCrawlColors, SubCrawlHelpers,
                   SubCrawlLogger, SubCrawlLoggerLevels)

try:
    from kafka import KafkaConsumer
    consumer = KafkaConsumer(
        'urls',
        bootstrap_servers=['kafka:9092'],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='urls-crawler',
        auto_commit_interval_ms=1000,
        consumer_timeout_ms=2000,
        value_deserializer=lambda x: json.loads(x.decode('utf-8')))
except:
    consumer = None

# region global variables and configs

# ignore TLS cert errors
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

process_pool = None

logger = None
global_cfg = None  # used in the main process
process_cfg = None  # used in the scraper processes
process_processing_modules = None  # used in the scraper process

init_pages = []  # initial found pages by splitting the url
crawl_pages = []  # found pages by scraping the initial urls

storage_modules = []
processing_modules = []

# endregion


def initialize():
    global logger, global_cfg, process_pool

    with open("config.yml", "r") as ymlfile:
        global_cfg = yaml.safe_load(ymlfile)

    if not global_cfg:
        print('[!] Error loading configuration file, engine could not start')
        sys.exit(0)

    logger = SubCrawlLogger("subcrawl.log", "SubCrawl",
                            SubCrawlLoggerLevels[SubCrawlHelpers.get_config(
                             global_cfg, 'crawler',
                             'log_level').upper()].value).get_logger()


def main(argv):

    banner = SubCrawlBanner(SubCrawlHelpers.get_config(
                            global_cfg, "crawler", "logos_path"),
                            SubCrawlHelpers.get_config(global_cfg,
                            "crawler", "tag_line"))
    banner.print_banner()

    options = setup_args(argv)

    start_time = datetime.datetime.now()

    # region process storage/payload modules

    str_storage_modules = list()
    if options.storage_modules:
        for storage_module in options.storage_modules.split(","):
            str_storage_modules.append(storage_module)
    else:
        for storage_module in SubCrawlHelpers.get_config(global_cfg, "crawler",
                                                         "storage_modules"):
            str_storage_modules.append(storage_module)

    for storage_module in str_storage_modules:
        try:
            dynamic_class = str2Class(storage_module.strip())
            storage_modules.append(dynamic_class(global_cfg, logger))
            logger.info("[ENGINE] Loaded storage module: " + storage_module)
        except Exception as e:
            logger.error("[ENGINE] Error loading storage module: " + storage_module)

    str_processing_modules = list()
    if options.processing_modules:
        for processing_module in options.processing_modules.split(","):
            str_processing_modules.append(processing_module)
    else:
        for processing_module in SubCrawlHelpers.get_config(global_cfg, "crawler", "processing_modules"):
            str_processing_modules.append(str(processing_module))

    for processing_module in str_processing_modules:
        try:
            dynamic_class = str2Class(processing_module.strip())
            processing_modules.append(dynamic_class(global_cfg, logger))
            logger.info("[ENGINE] Loaded processing module: " + processing_module)
        except Exception as e:
            logger.error("[ENGINE] Error loading processing module: " + processing_module + ": " + str(e))

    # endregion

    cpus = cpu_count()
    if cpus > 1:
        cpus = cpus - 1
    process_pool = ProcessPoolExecutor(cpus)

    scrape_urls = set()
    scraped_domains = set()
    for s_module in storage_modules:
        scraped_domains.update(s_module.load_scraped_domains())

    logger.info("[ENGINE] Parsing input sources...")

    # region gather input URLs
    if options.kafka and consumer:
        logger.info("[ENGINE] Using Kafka queue for URL processing...")
        for message in consumer:
            url = message.value
            if SubCrawlHelpers.is_valid_url(url):
                parsed = urlparse(url)
                if parsed.netloc not in scraped_domains:
                    parsed_url = url
                    if not url.endswith("/"):
                        parsed_url = remove_url_resource(url)
                    if parsed_url:
                        scrape_urls.add(parsed_url)
                    scraped_domains.add(parsed.netloc)
                else:
                    logger.debug("[~] Domain already added to the scanning queue: "
                                          + str(parsed.netloc))
    else:
        logger.info("[ENGINE] Using file input for URL processing...")
        try:
            with open(options.file_path, 'r') as f:
                for url in f:
                    if SubCrawlHelpers.is_valid_url(url):
                        parsed = urlparse(url)
                        if parsed.netloc not in scraped_domains:
                            parsed_url = url
                            if not url.endswith("/"):
                                parsed_url = remove_url_resource(url)
                            if parsed_url:
                                scrape_urls.add(parsed_url)
                            scraped_domains.add(parsed.netloc)
                        else:
                            logger.debug("[ENGINE] Domain already added to the scanning queue: " + str(parsed.netloc))  
        except Exception as e:
            logger.error("[ENGINE] Error reading input file for URL processing: " + str(e))
            sys.exit(-1)
            
    logger.info("[ENGINE] Found " + str(len(scrape_urls)) + " hosts to scrape")

    # endregion  

    # region generate new URLs

    domain_urls = dict()
    distinct_urls = list()
    for start_url in scrape_urls:
        parsed = urlparse(start_url)
        base = parsed.scheme + "://" + parsed.netloc
        paths = parsed.path[:-1].split('/')  # remove the trailing '/' to avoid an empty path
        tmp_url = base

        if not SubCrawlHelpers.get_config(global_cfg, "crawler", "scan_simple_domains") and len(paths) == 1 and paths[0] == "":
            continue  # don't scan simple domains.

        for path in paths:
            tmp_url = urljoin(tmp_url, path) + "/"

            logger.debug("Generated new URL: " + tmp_url)

            if tmp_url not in distinct_urls:
                distinct_urls.append(tmp_url)
                domain_urls.setdefault(parsed.netloc, []).append(tmp_url)

    # endregion

    logger.info("[ENGINE] Done parsing URLs, ready to begin scraping " + str(len(domain_urls)) + " hosts and " + str(len(distinct_urls)) + " URLs... starting in " + str(SubCrawlHelpers.get_config(global_cfg, "crawler", "delay_execution_time")) + " seconds!")
    time.sleep(int(SubCrawlHelpers.get_config(global_cfg, "crawler",
                                              "delay_execution_time")))

    # region crawl

    # used to convert url dict per domain into list of lists
    list_of_domains = list()
    for domain in domain_urls:
        url_list = list()
        for url in domain_urls[domain]:
            url_list.append(url)
        list_of_domains.append((url_list, global_cfg, processing_modules))

    # batch defines amount of domains to scan before calling storage modules
    for batch_urls in chunks(list_of_domains,
                             SubCrawlHelpers.get_config(global_cfg, "crawler",
                                                        "batch_size")):
        scrape_data = []  # result data of url scraping
        final_crawl_pages = set()
        result_dicts = process_pool.map(scrape_manager, batch_urls)

        original = dict()
        for result in result_dicts:
            merge(original, result, strategy=Strategy.ADDITIVE)

        scrape_data = original["scrape_data"] if "scrape_data" in original \
            else dict()
        crawl_pages = set(original["crawl_pages"]) if "crawl_pages" in \
            original else set()
        final_crawl_pages.update(crawl_pages)

        for s_module in storage_modules:
            s_module.store_result(scrape_data)

    elapsed = datetime.datetime.now() - start_time
    logger.info("Execution time (D:H:M:S): %02d:%02d:%02d:%02d" % (elapsed.days, elapsed.seconds // 3600, elapsed.seconds // 60 % 60, elapsed.seconds % 60))

    # endregion


def scrape_manager(data):
    domain_urls, cfg, processing_modules = data
    global process_cfg
    global init_pages
    global process_processing_modules

    process_cfg = cfg
    init_pages = domain_urls
    process_processing_modules = processing_modules

    logger.debug("[ENGINE] Starting down path... " + domain_urls[0])

    result_dicts = list()
    for url in domain_urls:
        s_data = []
        scrape_result = scrape(url, s_data)
        result_dicts.append(scrape_result)

    original = dict()
    for result in result_dicts:
        if "scrape_data" in result:
            result["scrape_data"] = json.loads(result["scrape_data"])
        merge(original, result, strategy=Strategy.ADDITIVE)

    return original


def scrape(start_url, s_data):
    try:
        scrape_domain = dict()
        request_start = datetime.datetime.now()
        logger.debug("[ENGINE] Scanning URL: " + start_url)
        resp = requests.get(start_url, timeout=SubCrawlHelpers.get_config(
            process_cfg, "crawler", "http_request_timeout"),
            headers=SubCrawlHelpers.get_config(process_cfg, "crawler",
                                               "headers"),
            verify=False, allow_redirects=SubCrawlHelpers.get_config(process_cfg, "crawler",
                                               "follow_redirects"),)

        if resp.status_code == 200:
            response_size_ok = True
            size = 0
            maxsize = SubCrawlHelpers.get_config(process_cfg, "crawler",
                                                 "http_max_size")
            ctt = BytesIO()

            for chunk in resp.iter_content(2048):
                size += len(chunk)
                ctt.write(chunk)
                current_time = datetime.datetime.now()
                if size > maxsize or \
                    (current_time - request_start).total_seconds() > \
                        SubCrawlHelpers.get_config(process_cfg, "crawler",
                                                   "http_download_timeout"):
                    resp.close()
                    response_size_ok = False
                    logger.debug("[ENGINE] Response too large or download timeout: " + start_url)
                    break

            if response_size_ok:
                content = ctt.getvalue()
                signature = ""
                title = None
                bs = None
                content_magic = "NONE"
                try:
                    bs = BeautifulSoup(str(content), "html.parser")
                    title = bs.find('title')
                except:
                    bs = None
                content_magic = magic.from_buffer(content).lower()
                module_results = {}
                if title is not None and \
                    "index of" in title.get_text().lower() \
                        and bs is not None:

                    for link in bs.find_all('a'):
                        if link.has_attr('href'):
                            href = link.attrs['href']
                            if href is not None and not href.startswith("?"):
                                next_page = urljoin(start_url, href)

                                if next_page not in crawl_pages and next_page not in init_pages \
                                    and not next_page.lower().endswith(tuple(SubCrawlHelpers.get_config(process_cfg, "crawler", "ext_exclude"))):
                                    logger.debug("[ENGINE] Discovered: " + next_page)
                                    crawl_pages.append(next_page)
                                    scrape(next_page, s_data)                
                else:
                    for p_module in process_processing_modules:
                        mod_res = p_module.process(start_url, content)
                        if mod_res:
                            module_results[type(p_module).__name__] = mod_res

                title = bs.select_one('title')
                if title:
                    title = title.string

                try:
                    text = base64.b64encode(content).decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.error("[ENGINE] " + str(e))

                scrape_entry = {
                    'scraped_on': datetime.datetime.now().isoformat(),
                    'sha256': SubCrawlHelpers.get_sha256(content),
                    'url': start_url,
                    'content_type': content_magic,
                    'signature': signature,
                    'data': {
                        'text': text,
                        'title': title,
                        'resp': {
                            'headers': dict(resp.headers) if resp else '',
                            'status_code': resp.status_code if resp else '',
                        },
                    },
                    "modules": {}
                }

                scrape_entry["modules"] = module_results
                s_data.append(scrape_entry)
                parsed = urlparse(start_url)
                scrape_domain = {parsed.netloc: s_data}

    except Exception as e:
        logger.debug("[ENGINE] " + str(e))

    return {"crawl_pages": crawl_pages, "scrape_data": json.dumps(scrape_domain)}


def remove_url_resource(unparsed_url):
    try:
        regex = r"\b((?:https?://)(?:(?:www\.)?(?:[\da-z\.-]+)\.(?:[a-z]{2,8})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?(?:(?:/[\w\.-]*)*/)?)\b"
        match = re.search(regex, unparsed_url, re.IGNORECASE)
        return match.group()
    except Exception as e:
        logger.error("[URL_PARSER] Error with URL " + unparsed_url + str(e))
        return None


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def unique_content(content):
    unique_dict = dict()
    for key in content:
        unique_dict[key] = set(content[key])
    return unique_dict


def str2Class(str):
    return getattr(sys.modules[__name__], str)


def print_classes():
    clsmembers_storage = inspect.getmembers(sys.modules["storage"], inspect.isclass)
    clsmembers_processing = inspect.getmembers(sys.modules["processing"], inspect.isclass)

    print("\n  Available processing modules: ")
    for mod in clsmembers_processing:
        print("  - " + mod[0])

    print("\n  Available storage modules: ")
    for mod in clsmembers_storage:
        print("  - " + mod[0])


def setup_args(argv):
    parser = argparse.ArgumentParser(description="")

    parser.add_argument('-f', '--file', action="store", dest="file_path", help="Path of input URL file")

    parser.add_argument('-k', '--kafka', action="store_true", dest="kafka", help="Use Kafka Queue as input")

    parser.add_argument('-p', '--processing', action="store", dest="processing_modules", help="Processing modules to be executed comma separated.")

    parser.add_argument('-s', '--storage', action="store", dest="storage_modules", help="Storage modules to be executed comma separated.")

    if len(argv) == 0:
        parser.print_help()
        print_classes()
        sys.exit(0)

    return parser.parse_args()


initialize()

if __name__ == '__main__':
    main(sys.argv[1:])
