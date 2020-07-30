#!/usr/bin/env python

#---------START CONFIG----------#
class CONFIG:
	pymisp_cmd_time = "1h"  # query PyMISP in time windows last 1 hour
	
	#insert_mode = "manual"
	#insert_only_tm must be use with manual mode
	insert_only_tm = "true" 
	
	# config for Apex Central integration
	use_url_base = 'https://8.8.8.8' 
	use_application_id = '7BB7B7E5-0000-1111-B9AE-7DD7E05941D6'
	use_api_key = '6549019E-0000-1111-ABA6-3F423AD418C5'  
	# Apex file_so action must be 'log' or 'block' or 'quarantine'
	use_action = 'log'
	
	# config for Deep Security
	# for Cloud One Workload security, ds_url_base = 'https://app.deepsecurity.trendmicro.com'
	ds_url_base = 'https://8.8.8.8:4119'
	ds_api_key = '2C0BF435-0000-1111-983B-4C2311F82DF3:nEaGaILarcAZLOrhMKkrX7SbfOuqtRkSIHC9wYlkY+I='

#---------END CONFIG----------#
