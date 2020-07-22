#!/bin/bash
# TM-MISP update script for update TM-MISP to MISP machine

# check permission
if [[ $EUID -ne 0 ]]; then
   echo "This TM-MISP Update script must be run as root" 
   exit 1
fi


if [ "$#" -ne 1 ]; then
# normal
curl https://raw.githubusercontent.com/chackco/tm-misp/master/tm-api.py --output /var/www/MISP/PyMISP/examples/tm-api.py
curl https://raw.githubusercontent.com/chackco/tm-misp/master/tm-manual-submision.py --output /var/www/MISP/PyMISP/examples/tm-manual-submision.py
curl https://raw.githubusercontent.com/chackco/tm-misp/master/list_apex_so.py --output /var/www/MISP/PyMISP/examples/list_apex_so.py
curl https://raw.githubusercontent.com/chackco/tm-misp/master/list_ds_so.py --output /var/www/MISP/PyMISP/examples/list_ds_so.py
curl https://raw.githubusercontent.com/chackco/tm-misp/master/tm-misp.php --output /var/www/MISP/app/webroot/tm-misp.php
curl https://raw.githubusercontent.com/chackco/tm-misp/master/tm-list.php --output /var/www/MISP/app/webroot/tm-list.php
curl https://raw.githubusercontent.com/chackco/tm-misp/master/main.css --output /var/www/MISP/app/webroot/main.css
curl https://raw.githubusercontent.com/chackco/tm-misp/master/OpenSans-Regular.ttf --output /var/www/MISP/app/webroot/OpenSans-Regular.ttf


else
# proxy mode
    echo "Detect proxy: $1"
curl -x $1 https://raw.githubusercontent.com/chackco/tm-misp/master/tm-api.py --output /var/www/MISP/PyMISP/examples/tm-api.py
curl -x $1 https://raw.githubusercontent.com/chackco/tm-misp/master/tm-manual-submision.py --output /var/www/MISP/PyMISP/examples/tm-manual-submision.py
curl -x $1 https://raw.githubusercontent.com/chackco/tm-misp/master/list_apex_so.py --output /var/www/MISP/PyMISP/examples/list_apex_so.py
curl -x $1 https://raw.githubusercontent.com/chackco/tm-misp/master/list_ds_so.py --output /var/www/MISP/PyMISP/examples/list_ds_so.py
curl -x $1 https://raw.githubusercontent.com/chackco/tm-misp/master/tm-misp.php --output /var/www/MISP/app/webroot/tm-misp.php
curl -x $1 https://raw.githubusercontent.com/chackco/tm-misp/master/tm-list.php --output /var/www/MISP/app/webroot/tm-list.php
curl -x $1 https://raw.githubusercontent.com/chackco/tm-misp/master/main.css --output /var/www/MISP/app/webroot/main.css
curl -x $1 https://raw.githubusercontent.com/chackco/tm-misp/master/OpenSans-Regular.ttf --output /var/www/MISP/app/webroot/OpenSans-Regular.ttf


fi

cd /var/www/MISP/PyMISP/examples
echo "Download TM-MISP and update to latest version" 
chown www-data:www-data tm-api.py
chown www-data:www-data tm-manual-submision.py
chown www-data:www-data list_apex_so.py
chown www-data:www-data list_ds_so.py
chown www-data:www-data /var/www/MISP/app/webroot/tm-misp.php
chown www-data:www-data /var/www/MISP/app/webroot/tm-list.php
chown www-data:www-data /var/www/MISP/app/webroot/main.css
chown www-data:www-data /var/www/MISP/app/webroot/OpenSans-Regular.ttf
touch /var/www/MISP/PyMISP/examples/waiting.txt
chown www-data:www-data /var/www/MISP/PyMISP/examples/waiting.txt
touch /var/www/MISP/PyMISP/examples/sending.txt
chown www-data:www-data /var/www/MISP/PyMISP/examples/sending.txt
echo '#!/bin/bash' > /home/misp/tm-api.sh
echo 'cd /var/www/MISP/PyMISP/examples' >> /home/misp/tm-api.sh
echo 'python3 tm-api.py' >> /home/misp/tm-api.sh
echo 'python3 tm-manual-submision.py' >> /home/misp/tm-api.sh
echo 'truncate -s 0 sending.txt' >> /home/misp/tm-api.sh
echo 'python3 list_apex_so.py > /var/www/MISP/PyMISP/examples/list_apex_so.txt'  >> /home/misp/tm-api.sh
echo 'python3 list_ds_so.py > /var/www/MISP/PyMISP/examples/list_ds_so.txt'  >> /home/misp/tm-api.sh
chmod +x /home/misp/tm-api.sh
echo "Finish updated."
