# © Copyright 2021 HP Development Company, L.P.
import hashlib
from io import BytesIO

import clamd

from .default_processing import DefaultProcessing
from utils import SubCrawlColors, SubCrawlHelpers

# Installation ClamAV for this Module
# sudo apt-get install clamav-daemon clamav-freshclam clamav-unofficial-sigs
# sudo freshclam
# sudo service clamav-daemon start


class ClamAVProcessing(DefaultProcessing):

    cfg = None
    cd = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger
        self.cd = clamd.ClamdUnixSocket()

    def process(self, url, content):
        scan_results = {}
        # self.cd = clamd.ClamdUnixSocket()
        # pong = self.cd.ping() # Will crash if not correctly installed. Handled in main crawler.
        buffer = BytesIO(content)
        scan_results = self.cd.instream(buffer)
        scan_results['url'] = url
        scan_results['hash'] = SubCrawlHelpers.get_sha256(content)

        try:
            if "OK" in scan_results['stream']:
                scan_results = {}
            else:
                clamav_status = str(scan_results['stream']).split(',')
                label = clamav_status[1].replace("'", '').replace(')', '').strip()
                scan_results['matches'] = label
                self.logger.info('[CLAMAV] Found - ' + label)
        except Exception as e:
            self.logger.error('[CLAMAV] ' + str(e))
            scan_results = {}
        return scan_results
