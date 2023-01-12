# © Copyright 2021 HP Development Company, L.P.
import csv
import io
import logging
import os
import sys
from datetime import datetime, timedelta
from json import dumps, loads

import requests
from kafka import KafkaConsumer, KafkaProducer
from timeloop import Timeloop

producer = KafkaProducer(bootstrap_servers=['kafka:9092'], value_serializer=lambda x: dumps(x).encode('utf-8'))
consumer = KafkaConsumer(
    'urls',
    bootstrap_servers=['kafka:9092'],
    auto_offset_reset='earliest',
    enable_auto_commit=False,
    group_id='urls-dedup',
    consumer_timeout_ms=2000,
    auto_commit_interval_ms=1000,
    value_deserializer=lambda x: loads(x.decode('utf-8')))

PHISHTANK_API = "http://data.phishtank.com/data/online-valid.csv"
tl = Timeloop()
urls = set()


# consume all urls from kafka and dedup
def load_urls():
    global urls
    try:
        for message in consumer:
            urls.add(message.value)
    except Exception as e:
        print(e)


@tl.job(interval=timedelta(seconds=300))
def phishtank():
    global urls
    if len(urls) == 0:
        load_urls()

    try:
        r = requests.get(PHISHTANK_API, allow_redirects=True)
        csv_data = io.StringIO(r.content.decode("utf-8"))
        csv_reader = csv.DictReader(csv_data)
        for row in csv_reader:
            url = row["url"]
            if url not in urls:
                producer.send('urls', value=url)
                urls.add(url)
    except Exception as e:
        print(e)
        pass  # Could not download file. Try again in a few seconds.


tl.start(block=True)
