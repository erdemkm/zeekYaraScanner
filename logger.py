#!/usr/bin/python3
# -*- coding: utf-8 -*-
__author__ = "Erdem Kucukmustafa"

import logging
from datetime import datetime, timedelta

logger = logging.getLogger('zeekYara')
handler = logging.FileHandler('logs/log_{:%Y-%m-%d}.log'.format(datetime.now()),mode='a')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


alertlogger = logging.getLogger('zeekYaraAlert')
handler = logging.FileHandler('logs/alertlog_{:%Y-%m-%d}.log'.format(datetime.now()),mode='a')
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
alertlogger.addHandler(handler)
alertlogger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
alertlogger.addHandler(stream_handler)

picuslogger = logging.getLogger('zeekYaraPicus')
handler = logging.FileHandler('logs/picuslog_{:%Y-%m-%d}.log'.format(datetime.now()),mode='a')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
picuslogger.addHandler(handler)
picuslogger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
picuslogger.addHandler(stream_handler)
