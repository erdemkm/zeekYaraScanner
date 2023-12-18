#!/usr/bin/python3
# -*- coding: utf-8 -*-
__author__ = "Erdem Kucukmustafa"

### Yara Configuration
yara_rule_file = "rules/rules.yar" # Yara rule file path
yara_scan_dir = "/opt/zeek/extracted" # zeek file extract path
max_file_size_mb = 20 # max file size for files to scan
match_timeout = 60 # timeout in seconds
scan_file_time_limit = 1 # (if this variable is set 0, there is no time limit for zeek extracted file. It means scan files from last x hours.)

### Zeek Extracted File Configuration
remove_scanned_file = False # (if True, zeek extracted files scanned with yara will be deleted after scanning.)

### Picus Configuration
picus_server = "" # Picus URL
picus_apikey = "" # Picus Refresh Token
attacker_peer = "" # Attacker Peer Name
victim_peer = "" # Victim Peer Name
variant = "" # Can be HTTP or HTTPS
products = "" # This parameter can be Check Point NGFW, ForcepointNGFW, McAfee IPS, PaloAlto IPS, SourceFire IPS, TippingPoint, F5 BIG-IP, Fortigate WAF, FortiWeb, Fortigate IPS, Snort, CitrixWAF, and ModSecurity.
