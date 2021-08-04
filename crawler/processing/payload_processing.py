# © Copyright 2021 HP Development Company, L.P.
import hashlib
import os
import magic
from utils import SubCrawlColors, SubCrawlHelpers

from .default_processing import DefaultProcessing


class PayloadProcessing(DefaultProcessing):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

        if not os.path.exists(SubCrawlHelpers.get_config(
                              self.cfg, "crawler", "download_dir")):
            os.makedirs(SubCrawlHelpers.get_config(
                         self.cfg, "crawler", "download_dir"))

    def process(self, url, content):
        payload = {}
        content_match = True
        file_ext = ""

        shasum = SubCrawlHelpers.get_sha256(content)
        content_magic = magic.from_buffer(content).lower()
        matches = content_magic

        if any(partial in content_magic for partial in
               SubCrawlHelpers.get_config(self.cfg, "crawler", "pe_magics")):
            self.logger.info(SubCrawlColors.CYAN + "[PAYLOAD] PE file found " +
                             url + " (" + shasum + ")" + SubCrawlColors.RESET)

            file_ext = ".bin"
            if "(dll)" in content_magic:
                file_ext = ".dll" + file_ext
            elif "x86-64" in content_magic:
                file_ext = ".64.exe" + file_ext
            else:
                file_ext = ".exe" + file_ext

        elif any(partial in content_magic for partial in
                 SubCrawlHelpers.get_config(self.cfg, "crawler",
                                            "archive_magics")):
            self.logger.info(SubCrawlColors.CYAN + "[PAYLOAD] ZIP found at " +
                             url + " (" + shasum + ")" + SubCrawlColors.RESET)
            file_ext = ".zip.bin"
        elif any(partial in content_magic for partial in
                 SubCrawlHelpers.get_config(self.cfg, "crawler",
                                            "php_magics")):
            self.logger.info(SubCrawlColors.CYAN + "[PAYLOAD] PHP found at " +
                             url + " (" + shasum + ")" + SubCrawlColors.RESET)
            file_ext = ".php.bin"
        elif any(partial in content_magic for partial in
                 SubCrawlHelpers.get_config(self.cfg, "crawler",
                                            "office_magics")):
            self.logger.info(SubCrawlColors.CYAN + "[PAYLOAD] Doc found at " +
                             url + " (" + shasum + ")" + SubCrawlColors.RESET)
            file_ext = ".office.bin"
        elif any(partial in content_magic for partial in
                 SubCrawlHelpers.get_config(self.cfg, "crawler",
                                            "elf_magics")):
            self.logger.info(SubCrawlColors.CYAN + "[PAYLOAD] ELF found at " +
                             url + " (" + shasum + ")" + SubCrawlColors.RESET)
            file_ext = ".elf.bin"
        else:
            content_match = False

        if content_match:
            payload = {"hash": shasum, "url": url, "matches": matches}

        if content_match and \
           SubCrawlHelpers.get_config(self.cfg, "crawler",
                                      "save_payload_content"):
            try:
                SubCrawlHelpers.save_content(
                    self.cfg['crawler']['download_dir'] +
                    shasum + file_ext, content)
                self.logger.info(SubCrawlColors.CYAN +
                                 "[PAYLOAD] Saved file " +
                                 SubCrawlHelpers.make_safe_http(url) +
                                 SubCrawlColors.RESET)
            except Exception as e:
                self.logger.error("[PAYLOAD] " + str(e))
                pass

        return payload
