#!/bin/bash
# TM-MISP install script for install TM-MISP to MISP machine

# check permission
if [[ $EUID -ne 0 ]]; then
   echo "This TM-MISP script must be run as root" 
   exit 1
fi

echo Install required Python library
pip3 install jwt
pip3 install PyJWT
cd /var/www/MISP/PyMISP/examples
cp keys.py.sample keys.py
chown www-data:www-data keys.py
echo Download TM-MISP 
curl https://raw.githubusercontent.com/chackco/tm-misp/master/tm-api.py --output /var/www/MISP/PyMISP/examples/tm-api.py
chown www-data:www-data tm-api.py
echo Finish, please edit config keys.py and tm-api.py