# © Copyright 2021 HP Development Company, L.P.
#####
# Probably not the easiest module to install. Needs protobuf-2.5.0 and python3.6 and of course sdhash
#
# Protobuf installation:
# > apt-get update
# > apt-get -y install libssl-dev libevent-pthreads-2.1-6 libomp-dev g++
# > apt-get -y install autoconf automake libtool curl make g++ unzip
# > wget https://github.com/protocolbuffers/protobuf/releases/download/v2.5.0/protobuf-2.5.0.zip
# > unzip protobuf-2.5.0.zip
# > cd protobuf-2.5.0
# > ./configure
# > make
# > sudo make install
#
# Python3.6 installation.
# > apt-get install python3.6-dev
# > sudo ldconfig
#
# SdHash installation:
# Use binaries from folder minisdhash or compile itself. If you chose the later -> have fun.
#

import os
import random
import string

from .default_processing import DefaultProcessing
from .minisdhash import sdbf_class as sdhash
from utils import SubCrawlHelpers, SubCrawlColors


class SDhashProcessing(DefaultProcessing):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def save_content(self, data):
        try:
            letters = string.ascii_lowercase
            filename = ''.join(random.choice(letters) for i in range(10))
            with open(SubCrawlHelpers.get_config(self.cfg, "crawler", "temp_dir") + filename, "wb") as file:
                file.write(data)
            return filename
        except Exception as e:
            self.logger.error("[SDHASH] Error: " + str(e))
            return ""

    def process(self, url, content):
        sd_result = {}
        if len(content) < 512:
            return {}

        try:
            file_name = self.save_content(content)
            if file_name:
                sd = sdhash.sdbf(SubCrawlHelpers.get_config(self.cfg, "crawler", "temp_dir") + file_name, 0)
                sd_result["sdhash"] = sd.to_string()
                sd_result["url"] = url
                os.remove(SubCrawlHelpers.get_config(self.cfg, "crawler", "temp_dir") + file_name,)
        except Exception as e:
            self.logger.error("[SDHASH] Error: " + str(e))
        return sd_result
