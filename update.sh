#!/bin/bash
# TM-MISP update script for update TM-MISP to MISP machine

# check permission
if [[ $EUID -ne 0 ]]; then
   echo "This TM-MISP Update script must be run as root" 
   exit 1
fi

cd /var/www/MISP/PyMISP/examples
echo "Download TM-MISP and update to latest version" 
curl https://raw.githubusercontent.com/chackco/tm-misp/master/tm-api.py --output /var/www/MISP/PyMISP/examples/tm-api.py
chown www-data:www-data tm-api.py
curl https://raw.githubusercontent.com/chackco/tm-misp/master/list_apex_so.py --output /var/www/MISP/PyMISP/examples/list_apex_so.py
chown www-data:www-data list_apex_so.py
curl https://raw.githubusercontent.com/chackco/tm-misp/master/list_ds_so.py --output /var/www/MISP/PyMISP/examples/list_ds_so.py
chown www-data:www-data list_ds_so.py
curl https://raw.githubusercontent.com/chackco/tm-misp/master/tm-misp.php --output /var/www/MISP/app/webroot/tm-misp.php
chown www-data:www-data /var/www/MISP/app/webroot/tm-misp.php
curl https://raw.githubusercontent.com/chackco/tm-misp/master/main.css --output /var/www/MISP/app/webroot/main.css
chown www-data:www-data /var/www/MISP/app/webroot/main.css
curl https://raw.githubusercontent.com/chackco/tm-misp/master/OpenSans-Regular.ttf --output /var/www/MISP/app/webroot/OpenSans-Regular.ttf
chown www-data:www-data /var/www/MISP/app/webroot/OpenSans-Regular.ttf
echo "Finish updated."
