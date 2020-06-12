#!/bin/bash
# TM-MISP install script for install TM-MISP to MISP machine

# check permission
if [[ $EUID -ne 0 ]]; then
   echo "This TM-MISP script must be run as root" 
   exit 1
fi

echo "Install required Python library"
pip3 install jwt
pip3 install PyJWT
cd /var/www/MISP/PyMISP/examples
cp keys.py.sample keys.py
chown www-data:www-data keys.py
echo "Download TM-MISP" 
curl https://raw.githubusercontent.com/chackco/tm-misp/master/tm-api.py --output /var/www/MISP/PyMISP/examples/tm-api.py
chown www-data:www-data tm-api.py
echo '#!/bin/bash' > /home/misp/tm-api.sh
echo 'cd /var/www/MISP/PyMISP/examples' >> /home/misp/tm-api.sh
echo 'python3 tm-api.py' >> /home/misp/tm-api.sh
chmod +x /home/misp/tm-api.sh
#write out current crontab
crontab -l > tmp_mycron
#echo new cron into cron file
echo "0 * * * * /home/misp/tm-api.sh" >> tmp_mycron
#install new cron file
crontab tmp_mycron
rm tmp_mycron
echo "Finish, please edit config keys.py and tm-api.py"
