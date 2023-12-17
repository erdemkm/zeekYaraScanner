#!/usr/bin/python3
# -*- coding: utf-8 -*-
__author__ = "Erdem Kucukmustafa"

import requests
import json
import config
import sys
from logger import picuslogger

def getAccessToken():

	picus_headers = {"X-Refresh-Token": "", "Content-Type": "application/json"}
	picus_headers["X-Refresh-Token"] = "Bearer " + config.picus_apikey

	picus_auth_endpoint = "/authenticator/v1/access-tokens/generate"
	picus_req_url = config.picus_server + picus_auth_endpoint
	try:
		picus_auth_response = requests.post(picus_req_url, headers=picus_headers, verify=False)
		picus_accessToken = json.loads(picus_auth_response.text)["data"]["access_token"]
	except Exception as e:
		picuslogger.error("Picus Authorization Error: make sure API Key or Picus URL is correctly set. Server is {}".format(config.picus_server))
		sys.exit(0)	

	return picus_accessToken

def getThreatWithSHA256(sha256):
	picus_endpoint = "/user-api/v1/threats/list"
	picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
	picus_threat_data = {"sha256":""}
	picus_threat_data["sha256"] = sha256
	try:
		picus_threat_response = requests.post(picus_req_url,headers=picus_headers,data=json.dumps(picus_threat_data),verify=False)
		picus_threat_json_result = json.loads(picus_threat_response.text)["data"]["threats"][0]
		pid = picus_threat_json_result["pid"]
		name = picus_threat_json_result["name"]
	except Exception as e:
		picuslogger.error("Can not fetch threat id with sha256({}) on Picus.".format(sha256))
		pid = name = "null"
	return pid,name

def generateEndpointURL(picus_accessToken,picus_endpoint):
	picus_server = config.picus_server
	endpointURL = picus_server + picus_endpoint
	picus_headers = {"X-Api-Token": "", "Content-Type": "application/json"}
	picus_headers["X-Api-Token"] = "Bearer " + picus_accessToken
	return endpointURL, picus_headers

def runAttacks(threat_id):
	threat_id = int(threat_id)
	picus_endpoint = "/user-api/v1/schedule/attack/single"
	picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
	picus_attack_data = {"trusted": config.victim_peer,"untrusted": config.attacker_peer,"threat_id": threat_id,"variant": config.variant}
	try:
		picus_attack_response = requests.post(picus_req_url,headers=picus_headers,data=json.dumps(picus_attack_data),verify=False)
	except Exception as e:
		picuslogger.error("Threat assessment failed on Picus.(ThreatId={})".format(threat_id))	

def getThreatResults(threat_id):
	threat_id = int(threat_id)
	picus_endpoint = "/user-api/v1/attack-results/threat-specific-latest"
	picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
	picus_threat_data = {"threat_id": threat_id}
	try:
		picus_threat_response = requests.post(picus_req_url,headers=picus_headers,data=json.dumps(picus_threat_data),verify=False)
		picus_threat_json_result = json.loads(picus_threat_response.text)["data"]["results"]
		vector_name = config.attacker_peer + " - " + config.victim_peer
		vectors_results = picus_threat_json_result["vectors"]

		for i in range(len(vectors_results)):
			if vectors_results[i]["name"] == vector_name:
				variants_results = vectors_results[i]["variants"]
				for j in range(len(variants_results)):
					if variants_results[j]["name"] == config.variant:
						threat_result = variants_results[j]["result"]
	except Exception as e:
		picuslogger.error("Can not fetch threat result on Picus.(ThreatId={})".format(threat_id))
		threat_result = "Unknown"	

	return threat_result

def getMitigation(threat_id):
	threat_id = int(threat_id)
	picus_products = config.products.split(",")
	picus_mitigation_results : Dict[str,Any] = {"results": []}
	picus_endpoint = "/user-api/v1/threats/mitigations/list"
	picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
	picus_threat_data = {"threat_id":threat_id,"products":picus_products}
	try:
		picus_mitigation_response = requests.post(picus_req_url,headers=picus_headers,data=json.dumps(picus_threat_data),verify=False)
		picus_mitigation_result = json.loads(picus_mitigation_response.text)["data"]["mitigations"]
		picus_mitigation_count = json.loads(picus_mitigation_response.text)["data"]["total_count"]
		if picus_mitigation_count!=0:
			for threat_mitigation in picus_mitigation_result:
				mitigation_data = {"threat_id":threat_mitigation["threat"]["id"],"signature_id":threat_mitigation["signature"]["id"],"signature_name":threat_mitigation["signature"]["name"],"vendor":threat_mitigation["product"]}
				picus_mitigation_results["results"].append(mitigation_data)

		picus_mitigation_results = picus_mitigation_results["results"]
	except Exception as e:
		picuslogger.error("Can not fetch threat mitigations on Picus.(ThreatId={})".format(threat_id))
		picus_mitigation_results = "null"

	return picus_mitigation_results
