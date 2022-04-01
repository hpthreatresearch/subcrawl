# © Copyright 2021 HP Development Company, L.P.
import io
import logging
import os
import sys
from datetime import datetime, timedelta

import yaml
from timeloop import Timeloop
from utils import SubCrawlColors, SubCrawlHelpers
from utils import check_topic

# check if kafka topic exists and create if needed
check_topic()
tl = Timeloop()


@tl.job(interval=timedelta(seconds=10))
def start_crawling():
    with open("config.yml", "r") as ymlfile:
        global_cfg = yaml.safe_load(ymlfile)

    if not global_cfg:
        sys.exit(0)

    processing_modules = list()
    for processing_module in SubCrawlHelpers.get_config(global_cfg, "crawler", "processing_modules"):
        processing_modules.append(processing_module)

    storage_modules = list()
    for storage_module in SubCrawlHelpers.get_config(global_cfg, "crawler", "storage_modules"):
        storage_modules.append(storage_module)

    try:
        os.system("/usr/local/bin/python3 subcrawl.py -k -p " + ",".join(processing_modules) + " -s " + ",".join(storage_modules))
    except Exception as e:
        print(e)


tl.start(block=True)
