#!/usr/bin/env python
# 
# Script will read SO from Apex and save to file for checking

import base64
import jwt
import hashlib
import requests
import time
import json
import urllib.parse
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
	
# Use this region to setup the call info of the Apex Central server (server url, application id, api key)



productAgentAPIPath = '/WebApp/api/SuspiciousObjects/UserDefinedSO/'
canonicalRequestHeaders = ''

useRequestBody = ''

useQueryString=""
jwt_token = create_jwt_token(CONFIG.use_application_id, CONFIG.use_api_key, 'GET',
                              productAgentAPIPath + useQueryString,
                              canonicalRequestHeaders, useRequestBody, iat=time.time())

headers = {'Authorization': 'Bearer ' + jwt_token , 'Content-Type': 'application/json;charset=utf-8'}
#Choose by call type.
r = requests.get(CONFIG.use_url_base + productAgentAPIPath + useQueryString, headers=headers, verify=False)

#print(r.status_code)
print(json.dumps(r.json(), indent=4))