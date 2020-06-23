#!/usr/bin/env python
# 
# Script will read SO from DS and save to file for checking

import base64
import jwt
import hashlib
import requests
import time
import json
import urllib.parse
from tmconfig import CONFIG




url_ds = CONFIG.ds_url_base + '/api/applicationcontrolglobalrules'
ds_key = CONFIG.ds_api_key
	
payload = {
}
	
useRequestBody = json.dumps(payload)  
headers = {'api-secret-key': ds_key, 'api-version': 'v1', 'Content-Type': "application/json"}
r = requests.get(url_ds, headers=headers, data=useRequestBody, verify=False) 
#if(r.status_code != 200):
#	print(r.status_code)
print(json.dumps(r.json(), indent=4))