#!/usr/bin/python3
# -*- coding: utf-8 -*-
__author__ = "Erdem Kucukmustafa"

import argparse
import zeekyara
from logger import alertlogger

def args_builder():
	logo = """
 ______          _     __   __                _____                                 
|___  /         | |    \ \ / /               /  ___|                                
   / /  ___  ___| | __  \ V /__ _ _ __ __ _  \ `--.  ___ __ _ _ __  _ __   ___ _ __ 
  / /  / _ \/ _ \ |/ /   \ // _` | '__/ _` |  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
./ /__|  __/  __/   <    | | (_| | | | (_| | /\__/ / (_| (_| | | | | | | |  __/ |   
\_____/\___|\___|_|\_\   \_/\__,_|_|  \__,_| \____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                                    
                                                                                    
"""
	parser = argparse.ArgumentParser(logo)
	parser.add_argument("-pcs","--picus",action="store_true",help="Start Picus Analysis and fetch mitigation for malicious files that matched yara rules.",default=False)
	parser.add_argument("-a","--analyzelogs",action="store_true",help="Analyze alert logs and get detail statistics.",default=False)
	args = parser.parse_args()
	return args

def main():
	args = args_builder()
	scanner = zeekyara.yaraScanner()
	scanner.ruleCompile()
	print("Start yara scanner for extracted zeek file...\n")
	scanner.runScanner()
	print("\nYara analysis done...\n")

	matches_count = len(scanner.matches)
	if matches_count>0:
		if args.picus:
			print("\nPicus Assessment and fetch mitigation for matched malicious file...\n")
			scanner.picusMatchedFileAnalysis()
			print("\nPicus processes done...\n")
		alertlogger.info("msg=Total yara rules match count for zeek extracted file:{}".format(matches_count))
	else:
		alertlogger.info("msg=No yara matches found for zeek extracted file.")

	if args.analyzelogs:
		if scanner.fetchMatchingLogs(args.picus):
			print("\n########## Start Log Analysis ##########")
			scanner.analyzeMatchingLogs(args.picus)

if __name__ == "__main__":
	main()
