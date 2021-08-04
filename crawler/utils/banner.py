# © Copyright 2021 HP Development Company, L.P.
import os
import random
import sys


class SubCrawlBanner():

    logo_path = ""
    tag_line = ""
    logos = []

    def __init__(self, logopath, tagline):
        self.logo_path = logopath
        self.tag_line = tagline
        for logo in os.listdir(self.logo_path):
            self.logos.append(os.path.join(self.logo_path, logo))

    def print_banner(self):
        logo = self.logos[random.randint(0, len(self.logos) - 1)]
        with open(logo) as logodata:
            print("\n" + logodata.read())
            print(self.tag_line + "\n")
