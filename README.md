# Beyond Endpoint Detection and Response using TM-MISP
### Written by Nathaphon K.

Nowadays, we are in the connected world, and the Threat landscape are evolving, we are targeted by automated hacking tools from hackers such as Exploit tool kit, Virus, Trojan, Ransomware, Keylogger etc. They have been a long history among the time. The clever one was creating the tool that can do polymorphic itself to evade from the detection engine like Antivirus, Sandbox. Then, in this new era, the security expert also need the advanced analysis and automation tool.

We have many well known security vendors in the market which have created their closed loop automation eco-system which work only for their products. In reality, customer will end up with many vendor in their environment for example, Firewall, Intrusion Prevention System, Email Gateway Security, Secure Web Gateway,  Security information and event management (SIEM), or Sandbox etc. The multi-vendor environment is very hard to managed. In the truth , there is no vendor that can guarantee that they will match every threat in the world. In this manner, customer will be need to add many effort for their day-to-day operation like check the Internet feed for new important IOC, then search for artifact in their network (i.e. IOC), add the user defined artifacts (i.e. IOC) in every security control points in their network to effectively block malicious one for their organization. Then, Tomorrow, they will need to redo everything again and again. 

<img width="561" alt="Rest API for automation" src="https://github.com/chackco/tm-misp/raw/master/images/api.png"> Figure 1: Rest API for Automation
 
We have many people try to solve this problem by created the centralize thing for automation including Security Orchestration, Automation and Response (SOAR) and threat intelligence sharing platform.  For example, MISP (Malware Information Sharing Platform), an Open Source Threat Intelligence Sharing Platform which designed for security engineer who want to share threat indicators using MISP or integrate MISP into other security monitoring tools, they also support one sharing to other organization like National CERT to their related organization. 

Trend Micro, as the global leader in cybersecurity, we also has concept of centralize visibility and management using Apex Central, the Apex Central support both automated Virtual Analyzer Suspicious Object (VASO) which receive from Deep Discovery family products (Sandbox) and User-defined Suspicious (UDSO) Object which support third party integration from external source using OpenIOC, STIX, and API automation, We also supported TAXII v1.x and v.2 automated feed management using Deep Discovery Director product. Trend Micro also has Deep Security Enterprise and Cloud One Workload Security product which support Application Control User-defined Suspicious Object (UDSO) using API automation.

## TM-MISP Project
TM-MISP project was created to joint Trend Micro CTD with MISP platform which will serve as bridge to synchronize IOC object from MISP to Trend Micro Apex Central (i.e. SHA-1 hash) and Deep Security/Cloud One Workload Security (i.e. SHA256) 

- Script will connected to MISP platform and gather SHA-1 and submit to Apex Central
- Script will also gather SHA256 and submit to Deep Security Manager/Cloud One Workload Security
- version 1.0 Start 1 June 2020, 13:18 GMT+7
- required library https://github.com/MISP/PyMISP

[Reference Architecture for this Project](images/arch.png)

## Pre-requisite
- Testing with MISP v.24.126@150b66d VMDK edition
- Download MISP VMDK (or other format) from https://www.circl.lu/misp-images/latest/
  i.e. Download file MISP_vX.X@YYYYY-VMware.zip
- Extract zip file and run VMware workstation, boot up waiting IP address (DHCP) i.e. 192.168.0.100
- SSH to MISP using user/pass = misp/Password1234
- Open browser to https://IP_of_MISP  i.e. https://192.168.0.100
- Login with admin@admin.test/admin
- Change password
- Click menu [Event Actions]>[Automation]> save text after "Your cuurent ket is" i.e. AAAAA

## Auto Installation Step
- > curl -L https://raw.githubusercontent.com/chackco/tm-misp/master/install.sh | bash -s
- > sudo vi keys.py
- change: misp_url to your url i.e. 'https://192.168.0.100'
- change: misp_key to your key i.e. 'AAAAA'
- change: misp_verifycert = false
- Sample
- > misp_url = 'https://192.168.0.100'
- > misp_key = 'AAAAA'
- > misp_verifycert = false
- save file
- Test connected
- > python3 last.py -l 1h

## Manual Installation Step

- Run command at shell > pip3 install pymisp
- > sudo pip3 install jwt
- > sudo pip3 install PyJWT
- > cd /var/www/MISP/PyMISP/examples
- > cp keys.py.sample keys.py
- > sudo chown www-data:www-data keys.py
- > sudo vi keys.py
- > edit misp_url to your url i.e. 'https://192.168.0.100'
- > edit misp_key to your key i.e. 'AAAAA'
- > edit misp_verifycert = false
- > save file
- Test connected 
- > python3 last.py -l 1h
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
