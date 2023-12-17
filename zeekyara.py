#!/usr/bin/python3
# -*- coding: utf-8 -*-
__author__ = "Erdem Kucukmustafa"

import yara
import os
import sys
from hashlib import sha256
import requests
from urllib3.exceptions import InsecureRequestWarning
from logger import logger, alertlogger, picuslogger
import config as conf
import picus
import time
from datetime import datetime, timedelta
import string
import random
from collections import defaultdict
from prettytable import PrettyTable


requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class yaraScanner:
	rules = None
	matches = []
	hasher = sha256()
	matching_lines = []

	def __init__(self):
		self.yara_rule_file = conf.yara_rule_file
		self.yara_scan_dir = conf.yara_scan_dir
		self.max_file_size_mb = conf.max_file_size_mb
		self.match_timeout = conf.match_timeout
		self.scan_file_time_limit = conf.scan_file_time_limit*60*60
		self.remove_scanned_file = conf.remove_scanned_file
			
	def ruleCompile(self):
		try:
			self.rules = yara.compile(filepath=self.yara_rule_file)
		except yara.SyntaxError as e:
			logger.error("msg=Unable to compile rules,reason={}".format(e))
			sys.exit(0)
		except Exception as e:
			logger.error("msg=An error occurred,reason={}".format(e))
			sys.exit(0)

	def runScanner(self):
		current_time = datetime.now().timestamp()
		for root,dirs,files in os.walk(self.yara_scan_dir):
			for file in files:
				rules_file_path = os.path.join(root, file)
				file_creation_time = datetime.fromtimestamp(os.path.getctime(rules_file_path)).timestamp()
				time_diff = current_time - file_creation_time
				if time_diff > self.scan_file_time_limit and self.scan_file_time_limit!=0:
					continue
				with open(rules_file_path,"rb") as f:
					scan_data = f.read()
					scan_data_size_mb = float("{:.2f}".format(len(scan_data)/1024/1024))
					if scan_data_size_mb > self.max_file_size_mb:
						continue
					try:
						rule_matches = self.rules.match(data=scan_data,timeout=self.match_timeout)
						if len(rule_matches) > 0:
							match_id = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
							matched_rule_list = ",".join(str(item) for item in rule_matches)
							self.hasher.update(scan_data)
							sha256 = self.hasher.hexdigest()
							self.matches.append((rules_file_path,sha256,matched_rule_list,match_id))
							alertlogger.info("match_id={},type=yaraalert,msg=Yara match found on zeek extracted file.,file={},sha256={},matchingrules={}".format(match_id,rules_file_path,sha256,matched_rule_list))
					except yara.TimeoutError as e:
						logger.error("msg=Timeout error,{}".format(e))
					except Exception as e:
						logger.error("msg=An error occurred,reason={}".format(e))

				if self.remove_scanned_file:
					try:
						os.remove(rules_file_path)
					except OSError as e:
						logger.error("msg=Error occurred while deleting {}: {}".format(rules_file_path,e))

	def picusMatchedFileAnalysis(self):
		for match in self.matches:
			matched_file_path = match[0]
			matched_file_sha256 = match[1]
			matched_rules = match[2]
			matched_id = match[3]
			pid, name = picus.getThreatWithSHA256(matched_file_sha256)
			if pid == "null":
				picuslogger.info("match_id={},type=picusinfo,msg=No threat was found on Picus for the malicious file matching the yara rules.,file={},sha256={},matchingrules={}".format(matched_id,matched_file_path,matched_file_sha256,matched_rules))
				continue
			picus.runAttacks(pid)
			time.sleep(60)
			threat_result = picus.getThreatResults(pid)
			if threat_result == "Insecure" or threat_result == "Unknown":
				mitigation_results = picus.getMitigation(pid)      
				for mitigation in mitigation_results:
					signature_id = mitigation["signature_id"]
					signature_name = mitigation["signature_name"]
					signature_vendor = mitigation["vendor"]
					msg = "match_id={},type=picusinsecurealert,msg=Malicious file that matched yara rule is insecure on Picus.file={},sha256={},matchingrules={},mitigation_id={},mitigation_name={},mitigation_vendor={}".format(matched_id,matched_file_path,matched_file_sha256,matched_rules,signature_id,signature_name,signature_vendor)
					picuslogger.info(msg)	
			elif threat_result == "Secure":
				picuslogger.info("match_id={},type=picussecurealert,msg=Malicious file that matched yara rule is secure on Picus.file={},sha256={},matchingrules={}".format(matched_id,matched_file_path,matched_file_sha256,matched_rules))

	def fetchMatchingLogs(self,picuslog=False):
		try:
			script_directory = os.path.dirname(os.path.abspath(__file__))
			alertlog_files = [f for f in os.listdir("logs") if f.startswith("alertlog")]
			log_files = alertlog_files

			if picuslog:
				picuslog_files = [f for f in os.listdir("logs") if f.startswith("picuslog")]
				log_files += picuslog_files

			for log_file in log_files:
				log_file_path = script_directory + "/" + os.path.join("logs", log_file)
				with open(log_file_path, "r") as file:
					for line in file:
						if "match_id" in line:
							self.matching_lines.append(line.strip())
			return True
		except Exception as e:
			logger.error("msg=Can not fetch matching logs,reason={}".format(e))
			print("\nCan not fetch matching logs. See logs for details.")
			return False

	def analyzeMatchingLogs(self,picuslog=False):
		current_time = datetime.now() 
		total_yaraalert_count = defaultdict(int)
		weekly_yaraalert_count = defaultdict(int)
		daily_yaraalert_count = defaultdict(int)
		
		if picuslog:
			total_picusalert_count = defaultdict(int)
			weekly_picusalert_count = defaultdict(int)
			daily_picusalert_count = defaultdict(int)
		
		for line in self.matching_lines:
			date_string = line.split(' ')[0] + ' ' + line.split(' ')[1]
			log_time = datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S,%f')
			
			if "type=yaraalert" in line:
				sha256 = line.split('sha256=')[1].split(',')[0]
				total_yaraalert_count[sha256] += 1

				if current_time - log_time <= timedelta(weeks=1):
					weekly_yaraalert_count[sha256] += 1

				if current_time - log_time <= timedelta(days=1):
					daily_yaraalert_count[sha256] += 1

			if picuslog:
				if "type=picusinsecurealert" in line:
					sha256 = line.split('sha256=')[1].split(',')[0]
					total_picusalert_count[sha256] += 1

				if current_time - log_time <= timedelta(weeks=1):
					weekly_picusalert_count[sha256] += 1

				if current_time - log_time <= timedelta(days=1):
					daily_picusalert_count[sha256] += 1

		total_yara_match = sum(1 for count in total_yaraalert_count.values() if count > 0)
		weekly_yara_match = sum(1 for count in weekly_yaraalert_count.values() if count > 0)
		daily_yara_match = sum(1 for count in daily_yaraalert_count.values() if count > 0)
	
		print("\n---------- Total, Weekly, Daily Yara Match Count (group by sha256) ----------\n")
		print("Total yara match={}\nWeekly yara match={}\nDaily yara match={}".format(total_yara_match,weekly_yara_match,daily_yara_match))

		top_5_yaramatch_by_hash = sorted(total_yaraalert_count.items(), key=lambda x: x[1], reverse=True)[:5]

		print("\n---------- Top 5 Yara Matches File ----------\n")
		top5_match_table = PrettyTable()	
		top5_match_table.field_names = ["Hash","Match Count"]
		for match in top_5_yaramatch_by_hash:
			top5_match_table.add_row(match)
		print(top5_match_table)

		if picuslog:
			total_picus_match = sum(1 for count in total_picusalert_count.values() if count > 0)
			weekly_picus_match = sum(1 for count in weekly_picusalert_count.values() if count > 0)
			daily_picus_match = sum(1 for count in daily_picusalert_count.values() if count > 0)

			print("\n---------- Total, Weekly, Daily Picus Insecure Result for Yara Matching (group by sha256) ----------\n")
			print("Total Insecure Picus match={}\nWeekly Insecure Picus match={}\nDaily Insecure Picus match={}".format(total_picus_match,weekly_picus_match,daily_picus_match))
