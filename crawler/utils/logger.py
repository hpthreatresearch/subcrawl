# © Copyright 2021 HP Development Company, L.P.
# source: https://www.toptal.com/python/in-depth-python-logging

import logging
import sys
import enum
from logging.handlers import TimedRotatingFileHandler
from utils.ansi_colors import SubCrawlColors


class SubCrawlLogger():

    formatter = None
    log_file = ""
    logger_name = ""
    log_level = logging.WARN

    def __init__(self, logfile, logger_name, log_level=logging.WARN):
        self.log_file = logfile
        self.logger_name = logger_name
        self.log_level = log_level
        self.formatter = CustomFormatter()

    def get_console_handler(self):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(self.formatter)
        return console_handler

    def get_file_handler(self):
        file_handler = TimedRotatingFileHandler(self.log_file, when='midnight')
        file_handler.setFormatter(self.formatter)
        return file_handler

    def get_logger(self):
        logger = logging.getLogger(self.logger_name)
        logger.setLevel(self.log_level)
        logger.addHandler(self.get_file_handler())
        logger.addHandler(self.get_console_handler())
        logger.propagate = False
        return logger


class SubCrawlLoggerLevels(enum.Enum):
    NOTSET = 0
    DEBUG = 10
    INFO = 20
    WARN = 30
    ERROR = 40
    CRITICAL = 50


class CustomFormatter(logging.Formatter):
    format = "%(asctime)s — %(name)s — %(levelname)s — %(message)s"

    FORMATS = {
        logging.DEBUG: SubCrawlColors.GREEN + format + SubCrawlColors.RESET,
        logging.INFO: SubCrawlColors.BLUE + format + SubCrawlColors.RESET,
        logging.WARNING: SubCrawlColors.YELLOW + format + SubCrawlColors.RESET,
        logging.ERROR: SubCrawlColors.RED + format + SubCrawlColors.RESET,
        logging.CRITICAL: SubCrawlColors.RED + format + SubCrawlColors.RESET
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
