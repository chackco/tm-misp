# tm-misp
### Writen by Nathaphon K.

Today, in the connected world, we are targeted by automated hacking tools from hackers such as exploit tool kit, virus, trojan, ransomware etc. They have been evolution a long the time. The clever one sometime can automate polymorphic itelf to evade the detection system like antivurs, so, security expert also need the automation tool tool.
We have many well kwown security vendors in the market which have created their closed loop automation ecosytem which work only for their product. In reality, customer will end up with many vendor in their environment for example, Firewall, Intrusion Prevention System, Email Security, Secure Web Gateway,  Security information and event management (SIEM), etc. The multi-vendor environment is hard to managed. In the truth , there is no vendor can garantee that they match every threat in the world, so, they need many effort for operation staff to operated including day-to-day operation like search for artifact (i.e. IOC), add user defined artifact (i.e. IOC) to block malicious one. The hardest part is to add those one-by-one in each product in the environment which need the skill, high learning curve and also take time. Some vendor also have sandbox system which can do automated malware analysis and provide generated IOC for detection. We need to push these detection into our defense system.  
We have many people try to solve this problem by created centralize thing for automation including threat intelligence sharing platform. 
MISP (Malware Information Sharing Platform) is an Open Source Threat Intelligence Sharing Platform
which designed for security engineer who want to share threat indicators using MISP or integrate MISP into other security monitoring tools, they support one sharing to other one 

Trend Micro also has concept centralize management using Apex Central, Apex Central 

- Script will connected to MISP platform and gather sha1 and submit to Apex Central
- then gather sha256 and submit to Deep Security
- version 1.0 Start 1 June 2020, 13:18 GMT+7
- required library https://github.com/MISP/PyMISP
#### Installation Step
- Testing with MISP v.24.126@150b66d VMDK edition
- Download MISP VMDK (or other format) from https://www.circl.lu/misp-images/latest/
  i.e. Download file MISP_vX.X@YYYYY-VMware.zip
- Extract zip file and run VMware workstation, boot up waiting IP address (DHCP) i.e. 192.168.0.100
- SSH to MISP using user/pass = misp/Password1234
- Open browser to https://IP_of_MISP  i.e. https://192.168.0.100
- Login with admin@admin.test/admin
- Change password
- Click menu [Event Actions]>[Automation]> save text after "Your cuurent ket is" i.e. AAAAA
- Run command at shell > pip3 install pymisp
- > sudo pip3 install jwt
- > cd /var/www/MISP/PyMISP/examples
- > cp keys.py.sample keys.py
- > sudo chown www-data:www-data keys.py
- > sudo vi keys.py
- > edit misp_url to your url i.e. 'https://192.168.0.100'
- > edit misp_key to your key i.e. 'AAAAA'
- > edit misp_verifycert = false
- > save file
- Run command at shell > python3 last.py -l 1h
- See if no error except unverified HTTPS request.... 
- Upload file tm-api.py to path above
- > sudo chown www-data:www-data tm-api.py
- > sudo vi tm-api.py
- Open Apex central > API key > create
- > edit use_url_base = https://Apex_central_ip
- > edit use_application_id = Apex application id
- > edit use_api_key = Apex api key
- Open Deep Security Manager > ADmin > API key > create
- > edit ds_url_base = https://dsm_ip:4119/api/applicationcontrolglobalrules
- > edit ds_api_key = Deep security api key
- > save file
- Run command at shell > python3 tm-api.py
