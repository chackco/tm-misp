# Trend Micro DDD IOC to MISP plugin
# written by Nathaphon K.

import json
from tmconfig import CONFIG
from taxii2client.v20 import  ApiRoot, Collection, Server, Status, as_pages

DDD_server=CONFIG.ddd_url


FILE_export_sha1='/var/www/MISP/app/webroot/tm-export-sha1.txt'
FILE_export_sha256='/var/www/MISP/app/webroot/examples/tm-export-sha256.txt'
FILE_export_url='/var/www/MISP/app/webroot/tm-export-url.txt'
FILE_export_domain='/var/www/MISP/app/webroot/tm-export-domain.txt'
FILE_export_ip='/var/www/MISP/app/webroot/tm-export-ip.txt'

##################################



server = Server(DDD_server + '/taxii/', user='admin', password='P@ssw0rd',verify=False)
print('->> ' + server.title)
api_root = server.api_roots[0]
print('->> ' + api_root.title)
file_sha1 = open(FILE_export_sha1,"w")
file_sha1.close()
file_sha256 = open(FILE_export_sha256,"w")
file_sha256.close()
file_url = open(FILE_export_url,"w")
file_url.close()
file_domain = open(FILE_export_domain,"w")
file_domain.close()
file_ip = open(FILE_export_ip,"w")
file_ip.close()

file_sha1 = open(FILE_export_sha1,"a")
file_sha256 = open(FILE_export_sha256,"a")
file_url = open(FILE_export_url,"a")
file_domain = open(FILE_export_domain,"a")
file_ip = open(FILE_export_ip,"a")

count_ioc=0
for col_x in api_root.collections:
    print('--->>>' + col_x.title + ' = ' + col_x.id)
    try:
        for bundle in as_pages(col_x.get_objects, per_request=1000):
            for bundle_key in bundle:
                if (bundle_key == 'objects'):
                    for objects_num in range(len(bundle['objects'])):
                        for bundle_obj_key in bundle['objects'][objects_num]:
                            if (bundle_obj_key == 'pattern'):
                                temp=bundle['objects'][objects_num][bundle_obj_key]
                                if ("SHA-1" in temp):
                                    print('-SHA1->',temp[24:-2])
                                    file_sha1.write(temp[24:-2] + "\n")
                                elif ("SHA-256" in temp):
                                    print('-SHA256->',temp[26:-2])
                                    file_sha256.write(temp[26:-2] + "\n")
                                elif ("url:value" in temp):
                                    print('-URL->',temp[14:-2])
                                    file_url.write(temp[14:-2] + "\n")
                                elif ("domain-name:value" in temp):
                                    print('-DOMAIN->',temp[22:-2])
                                    file_domain.write(temp[22:-2] + "\n")
                                elif ("ipv4-addr:value" in temp):
                                    print('-IP->',temp[20:-2])
                                    file_ip.write(temp[20:-2] + "\n")
                                else:
                                    print('----->',temp)
                                count_ioc=count_ioc+1
                    print('---------')
    except:
        pass
file_sha1.close()
file_sha256.close()
file_url.close()
file_domain.close()
file_ip.close()


print('total = ',count_ioc)

