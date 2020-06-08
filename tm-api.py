#!/usr/bin/env python
# Writen by nathaphon_k@trendmicro.com
# Script will connected to MISP platform and gather sha1 and submit to Apex Central
# then gather sha256 and submit to Deep Security
# version 1.0 build 1 June 2020, 13:18 GMT+7
# required library https://github.com/MISP/PyMISP

import subprocess
import base64
import jwt
import hashlib
import requests
import time
import json
import urllib.parse
import datetime
import datetime

#---------START CONFIG----------#
# need to crontab, for example schedule every 1 hour 
# 0 * * * * python3 tm-api.py
cmd = "python3 ./last.py -l 1h"  # query MISP in time windows last 1 hour

# config for Apex Central integration
use_url_base = 'https://172.16.1.164' 
use_application_id = '7BB7B7E5-47BA-4073-B9AE-7DD7E05941D6'
use_api_key = '6549019E-FBF2-428B-ABA6-3F423AD418C5'  

# config for Deep Security
ds_url_base = 'https://172.16.1.105:4119/api/applicationcontrolglobalrules'
ds_api_key = '2C0BF435-6EBA-2C4A-983B-4C2311F82DF3:nEaGaILarcAZLOrhMKkrX7SbfOuqtRkSIHC9wYlkY+I='

#---------END CONFIG----------#


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
         
		 
def submit_so_to_ds(sha256_so,url_ds, ds_key):
	
	payload = {
	  "applicationControlGlobalRules":[
		{
			"sha256":sha256_so,
			"description":"from MISP"
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
		 
def submit_so_to_apex(sha1_so, url_so, appid, appkey):
# Use this region to setup the call info of the Apex Central server (server url, application id, api key)
# server info


	productAgentAPIPath = '/WebApp/api/SuspiciousObjects/UserDefinedSO/'
	canonicalRequestHeaders = ''

	useQueryString = '' 
	val_so = sha1_so 
	val_date0 = datetime.datetime.now() + datetime.timedelta(days=30)
	val_date = val_date0.isoformat(timespec='minutes') + 'Z'
	payload = {
        "param":{
            "type":"file_sha1",
            "content":val_so,
            "notes":"from MISP",
            "scan_action":"log",
            "expiration_utc_date":val_date
        }
    }
	useRequestBody = json.dumps(payload)  
	print(f"payload = {useRequestBody}")
 
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

#-------------------------
print('-------- [ START RUN ] ------------\n')


returned_value = subprocess.check_output(cmd, shell=True)  # returns the exit code in unix
i = 0
j = 0
h = 0
m = 0
for returned_value2 in returned_value.splitlines():
	#print(f"RR {returned_value2}")
	if(returned_value2.decode('utf-8') != 'No results for that time period'):
		h = h + 1
		parsed = json.loads(returned_value2)
		for k,v in parsed.items():
			if(k == 'Attribute'):  #sha1 inside
				for lv1_attr in v:
					val_lv1_attr = lv1_attr.items()
					is_sha1_0 = 0
					is_sha256_0 = 0
					for val_lv1_attr_k, val_lv1_attr_v in val_lv1_attr:
						if(is_sha1_0 == 1 and val_lv1_attr_k == 'value'):
							is_sha1_0 = 0
							i = i + 1
							print(f">> sha1 <-> {val_lv1_attr_v}")
							submit_so_to_apex(val_lv1_attr_v, use_url_base, use_application_id, use_api_key)
						if(val_lv1_attr_v == 'sha1' or val_lv1_attr_v == '|sha1'):
							is_sha1_0 = 1
						if(is_sha256_0 == 1 and val_lv1_attr_k == 'value'):
							is_sha256_0 = 0
							m = m + 1
							print(f">> sha256 <-> {val_lv1_attr_v}")
							submit_so_to_ds(val_lv1_attr_v, ds_url_base, ds_api_key)
						if(val_lv1_attr_v == 'sha256' or val_lv1_attr_v == '|sha256'):
							is_sha256_0 = 1
			if(k == 'Object'):
				for k3 in v:
					val = k3.items()
					for k4,v4 in val:
						if(k4 == 'Attribute'): #sha1 inside
							j = j + 1
							v4_temp=json.dumps(v4)
							v4_json = json.loads(v4_temp)
							for k5 in v4:
								is_sha1 = 0
								is_sha256 = 0
								for k6,v6 in k5.items():
									if(is_sha1 == 1 and k6 == 'value'):
										is_sha1 = 0
										i = i + 1
										print(f">> sha1 <-> {v6}")
										submit_so_to_apex(v6, use_url_base, use_application_id, use_api_key)
									if(v6 == 'sha1' or v6 == '|sha1'):
										is_sha1 = 1
									if(is_sha256 == 1 and k6 == 'value'):
										is_sha256 = 0
										m = m + 1
										print(f">> sha256 <-> {v6}")
										submit_so_to_ds(v6, ds_url_base, ds_api_key)
									if(v6 == 'sha256' or v6 == '|sha256'):
										is_sha256 = 1
print(f"---- found sha1 = {i}, sha256 = {m}")

print('-------- [ END RUN ] ------------\n')


#--------------------------


		 
