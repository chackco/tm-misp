#!/usr/bin/env python

import base64
import jwt
import hashlib
import requests
import time
import json
import urllib.parse
import datetime
from tmconfig import CONFIG


def create_checksum(http_method, raw_url, headers, request_body):
        string_to_hash = http_method.upper() + '|' + raw_url.lower() + '|' + headers + '|' + request_body
        base64_string = base64.b64encode(hashlib.sha256(str.encode(string_to_hash)).digest()).decode('utf-8')
        return base64_string

def create_jwt_token(appication_id, api_key, http_method, raw_url, headers, request_body,
                                         iat=time.time(), algorithm='HS256', version='V1'):
    payload = {'appid': appication_id,
               'iat': iat,
               'version': version,
               'checksum': create_checksum(http_method, raw_url, headers, request_body)}
    token = jwt.encode(payload, api_key, algorithm=algorithm).decode('utf-8')
    return token 
         
		 
def submit_so_to_ds(sha256_so,url_ds, ds_key, s_sha1):
	if(url_ds == ''):
		return 1

	url_ds = url_ds + '/api/applicationcontrolglobalrules'
	s1 = ''
	if(s_sha1 != ''):
		s1 = ' - sha1=' + s_sha1
	payload = {
	  "applicationControlGlobalRules":[
		{
			"sha256":sha256_so,
			"description":"UDSO from TM-MISP" + s1
		}
		]
	}
	useRequestBody = json.dumps(payload)  
	headers = {'api-secret-key': ds_key, 'api-version': 'v1', 'Content-Type': "application/json"}
	r = requests.post(url_ds, headers=headers, data=useRequestBody, verify=False) 
	if(r.status_code != 200):
		print(r.status_code)
		print(json.dumps(r.json(), indent=4))

	
	return 0
		 
def submit_so_to_apex(sha1_so, url_so, appid, appkey, so_action, so_type):
# Use this region to setup the call info of the Apex Central server (server url, application id, api key)
# server info
	if(url_so == ''):
		return 1
# so_type = file_sha1 , url, domain, ip
	productAgentAPIPath = '/WebApp/api/SuspiciousObjects/UserDefinedSO/'
	canonicalRequestHeaders = ''

	useQueryString = '' 
	val_so = sha1_so 
	val_date0 = datetime.datetime.now() + datetime.timedelta(days=30)
	val_date = val_date0.isoformat(timespec='minutes') + 'Z'
	payload = {
        "param":{
            "type":so_type,
            "content":val_so,
            "notes":"UDSO from TM-MISP",
            "scan_action":so_action,
            "expiration_utc_date":val_date
        }
    }
	useRequestBody = json.dumps(payload)  
	#print(f"payload = {useRequestBody}")
 
	jwt_token = create_jwt_token(appid, appkey, 'PUT',
                                 productAgentAPIPath + useQueryString,
                                 canonicalRequestHeaders, useRequestBody, iat=time.time())

	headers = {'Authorization': 'Bearer ' + jwt_token, 'Content-Type': "application/json"}

	#Choose by call type. 
	r = requests.put(url_so + productAgentAPIPath + useQueryString, headers=headers, data=useRequestBody, verify=False) 

	if(r.status_code != 200):
		print(r.status_code)
		print(json.dumps(r.json(), indent=4))

	return 0


file1 = open("/var/www/MISP/PyMISP/examples/sending.txt","r") 

for returned_line in file1.readlines():
	if(returned_line.strip() != ''):
		print(">>" + returned_line.strip())
		txt = returned_line.strip().split("===")
		print(f"1={txt[0]}, 2={txt[1]}")
		if(txt[1] == 'file_sha256'):
			submit_so_to_ds(txt[0], CONFIG.ds_url_base, CONFIG.ds_api_key, txt[2])
		else:
			submit_so_to_apex(txt[0], CONFIG.use_url_base, CONFIG.use_application_id, CONFIG.use_api_key, CONFIG.use_action, txt[1])

file1.close()