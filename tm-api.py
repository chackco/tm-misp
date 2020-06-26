#!/usr/bin/env python
# Writen by nathaphon_k
# Script will connected to MISP platform and gather sha1 and submit to Apex Central
# then gather sha256 and submit to Deep Security
# version 0.1 build 1 June 2020, 13:18 GMT+7 - initial
# version 0.2 build 12 June 2020, 18:41 GMT+7 - add config option
# version 0.3 build 18 June 2020, 10:00 GMT+7 - change some option
# version 0.4 build 26 June 2020, 18:19 GMT+7 - add url, domain so support
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
from tmconfig import CONFIG

cmd = "python3 ./last.py -l " + CONFIG.pymisp_cmd_time 

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
# so_type = file_sha1 , url, domain
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

#-------------------------
print('-------- [ START RUN ] ------------\n')


returned_value = subprocess.check_output(cmd, shell=True)  # returns the exit code in unix
count_sha1 = 0
j = 0
count_url = 0
count_domain = 0
h = 0
count_sha256 = 0
for returned_value2 in returned_value.splitlines():
	#print(f"RR {returned_value2}")
	if(returned_value2.decode('utf-8') != 'No results for that time period'):
		h = h + 1
		parsed = json.loads(returned_value2)
		for k,v in parsed.items():
			if(k == 'Attribute'):  #sha1 inside
				save_sha1_0 = ''
				for lv1_attr in v:
					val_lv1_attr = lv1_attr.items()
					is_sha1_0 = 0
					is_url_0 = 0
					is_domain_0 = 0
					is_sha256_0 = 0
					for val_lv1_attr_k, val_lv1_attr_v in val_lv1_attr:
						if(is_domain_0 == 1 and val_lv1_attr_k == 'value'):
							is_domain_0 = 0
							count_domain = count_domain + 1
							#print(f" {save_sha1_0}")
							print(f">> domain <-> {val_lv1_attr_v}")
							submit_so_to_apex(val_lv1_attr_v, CONFIG.use_url_base, CONFIG.use_application_id, CONFIG.use_api_key, CONFIG.use_action, 'domain')
						if(val_lv1_attr_v == 'domain'):
							is_domain_0 = 1
						if(is_url_0 == 1 and val_lv1_attr_k == 'value'):
							is_url_0 = 0
							count_url = count_url + 1
							#print(f" {save_sha1_0}")
							print(f">> url <-> {val_lv1_attr_v}")
							submit_so_to_apex(val_lv1_attr_v, CONFIG.use_url_base, CONFIG.use_application_id, CONFIG.use_api_key, CONFIG.use_action, 'url')
						if(val_lv1_attr_v == 'url'):
							is_url_0 = 1
						if(is_sha1_0 == 1 and val_lv1_attr_k == 'value'):
							is_sha1_0 = 0
							count_sha1 = count_sha1 + 1
							save_sha1_0 = val_lv1_attr_v
							#print(f" {save_sha1_0}")
							print(f">> sha1 <-> {val_lv1_attr_v}")
							submit_so_to_apex(val_lv1_attr_v, CONFIG.use_url_base, CONFIG.use_application_id, CONFIG.use_api_key, CONFIG.use_action, 'file_sha1')
						if(val_lv1_attr_v == 'sha1' or val_lv1_attr_v == '|sha1'):
							is_sha1_0 = 1
							#save_sha1_0 = ''
						if(is_sha256_0 == 1 and val_lv1_attr_k == 'value'):
							is_sha256_0 = 0
							count_sha256 = count_sha256 + 1
							print(f">> sha256 <-> {val_lv1_attr_v}, {save_sha1_0}")
							submit_so_to_ds(val_lv1_attr_v, CONFIG.ds_url_base, CONFIG.ds_api_key,save_sha1_0)
							save_sha1_0 = ''
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
							save_sha1 = ''
							for k5 in v4:
								is_sha1 = 0
								is_url = 0
								is_domain = 0
								is_sha256 = 0
								for k6,v6 in k5.items():
									if(is_domain == 1 and k6 == 'value'):
										is_domain = 0
										count_domain = count_domain + 1
										print(f">> domain <-> {v6}")
										submit_so_to_apex(v6, CONFIG.use_url_base, CONFIG.use_application_id, CONFIG.use_api_key, CONFIG.use_action, 'domain')
									if(v6 == 'domain'):
										is_domain = 1
									if(is_url == 1 and k6 == 'value'):
										is_url = 0
										count_url = count_url + 1
										print(f">> url <-> {v6}")
										submit_so_to_apex(v6, CONFIG.use_url_base, CONFIG.use_application_id, CONFIG.use_api_key, CONFIG.use_action, 'url')
									if(v6 == 'url'):
										is_url = 1
									if(is_sha1 == 1 and k6 == 'value'):
										is_sha1 = 0
										count_sha1 = count_sha1 + 1
										print(f">> sha1 <-> {v6}")
										save_sha1 = v6
										submit_so_to_apex(v6, CONFIG.use_url_base, CONFIG.use_application_id, CONFIG.use_api_key, CONFIG.use_action, 'file_sha1')
									if(v6 == 'sha1' or v6 == '|sha1'):
										is_sha1 = 1
										#save_sha1 = ''
									if(is_sha256 == 1 and k6 == 'value'):
										is_sha256 = 0
										count_sha256 = count_sha256 + 1
										print(f">> sha256 <-> {v6}, {save_sha1}")
										submit_so_to_ds(v6, CONFIG.ds_url_base, CONFIG.ds_api_key, save_sha1)
										save_sha1=''
									if(v6 == 'sha256' or v6 == '|sha256'):
										is_sha256 = 1
print(f"---- found url = {count_url}, domain = {count_domain}, sha1 = {count_sha1}, sha256 = {count_sha256}")

print('-------- [ END RUN ] ------------\n')


#--------------------------


		 
