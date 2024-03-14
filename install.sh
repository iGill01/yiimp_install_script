#!/bin/bash
################################################################################
# Original Author:   Kudaraidee
# Modified by: Delari (https://github.com/xavatar/yiimp_install_scrypt)
# Modified by: Saltpool
# Program: v0.3 (update - February 2024)
#   Install yiimp on Ubuntu 22.04 running Nginx, MariaDB, and PHP 8.2
#   Yii 1.1.29 Framework (supports up to PHP 8.2)
################################################################################

   script_version='v0.3-8.2'
   yii_version='1.1.29'
   php_version='8.2'

    output() {
    printf "\E[0;33;40m"
    echo $1
    printf "\E[0m"ku
    }

    displayErr() {
    echo
    echo $1;
    echo
    exit 1;
    }

    #Add user group sudo + no password
    whoami=`whoami`
    sudo usermod -aG sudo ${whoami}
    echo '# yiimp
    # It needs passwordless sudo functionality.
    '""''"${whoami}"''""' ALL=(ALL) NOPASSWD:ALL
    ' | sudo -E tee /etc/sudoers.d/${whoami} >/dev/null 2>&1

    #Copy needed files
    sudo cp -r conf/functions.sh /etc/
    sudo cp -r utils/screen-script.sh /etc/
    sudo cp -r utils/screen-stratum.sh /etc/
    sudo cp -r conf/editconf.py /usr/bin/
    sudo cp -r utils/sources.list /etc/apt/
    sudo chmod +x /usr/bin/editconf.py
    sudo chmod +x /etc/screen-script.sh
    sudo chmod +x /etc/screen-stratum.sh

    source conf/functions.sh

    hide_output sudo apt -y update
    apt_install lsb-release figlet update-motd landscape-common update-notifier-common lolcat needrestart

    clear
    figlet -f slant -w 100 "Saltpool Yiimp Installer" | lolcat -f

    echo
    echo -e "$GREEN************************************************************************$COL_RESET"
    echo -e "$GREEN Yiimp Install Script $script_version $COL_RESET"
    echo -e "$GREEN Install yiimp on Ubuntu 22.04 running Nginx, MariaDB, and PHP $php_version $COL_RESET"
    echo -e "$GREEN Running under Yii Framework $yii_version $COL_RESET"
    echo -e "$GREEN************************************************************************$COL_RESET"
    echo
    sleep 3

    # Update package and Upgrade Ubuntu
    echo
    echo
    echo -e "$CYAN => Updating system and installing required packages:$COL_RESET"
    sleep 3

    sudo sed -i 's/#$nrconf{restart} = '"'"'i'"'"';/$nrconf{restart} = '"'"'a'"'"';/g' /etc/needrestart/needrestart.conf
    
    hide_output sudo apt -y upgrade
    hide_output sudo apt -y autoremove
    apt_install software-properties-common
    apt_install dialog python3 python3-pip acl nano apt-transport-https
    echo -e "$GREEN Done...$COL_RESET"

    source conf/prerequisite.sh
    sleep 3
    source conf/getip.sh

    echo 'PUBLIC_IP='"${PUBLIC_IP}"'
    PUBLIC_IPV6='"${PUBLIC_IPV6}"'
    DISTRO='"${DISTRO}"'
    PRIVATE_IP='"${PRIVATE_IP}"'' | sudo -E tee conf/pool.conf >/dev/null 2>&1

    echo
    echo
    echo -e "$YELLOW Make sure you double check before hitting enter! You only get one shot at these! $COL_RESET"
    echo
    read -e -p "Enter time zone (e.g. America/New York):" TIME
    read -e -p "Domain Name (no http:// just : example.com or pool.example.com (IP is ok, but not recommended) : " server_name
    read -e -p "Are you using a subdomain (pool.example.com?) [y/N]: " sub_domain
    read -e -p "Enter the name of your pool (a general name, not the domain, e.g., Saltpool: " poolname
    read -e -p "Enter support email (e.g. admin@example.com): " EMAIL
    read -e -p "Set Pool to AutoExchange? i.e. mine any coin with BTC address? [y/N]: " BTC
    read -e -p "Please enter a new location for /site/AdminPanel, if required. This is to customize the Admin Panel entrance url (e.g. myControlPanel): " admin_panel
    read -e -p "Enter the public IP of the system you will use to access the admin panel (IP of YOUR PC/internet connection where need to be access to Panel): " Public
    read -e -p "Install Fail2ban? [Y/n]: " install_fail2ban
    read -e -p "Install UFW and configure ports? [Y/n]: " UFW
    read -e -p "Install LetsEncrypt SSL? IMPORTANT! You MUST have your domain name pointed to this server prior to running the script!! [Y/n]: " ssl_install

    # Installing Nginx
    echo
    echo
    echo -e "$CYAN => Installing Nginx server: $COL_RESET"
    sleep 3

    if [ -f /usr/sbin/apache2 ]; then
    echo -e "Removing apache..."
    hide_output sudo apt-get -y purge apache2 apache2-*
    hide_output sudo apt-get -y --purge autoremove
    fi

    hide_output sudo apt -y install nginx
    hide_output sudo rm /etc/nginx/sites-enabled/default
    hide_output sudo systemctl start nginx.service
    hide_output sudo systemctl enable nginx.service
    hide_output sudo systemctl start cron.service
    hide_output sudo systemctl enable cron.service
    sleep 5
    sudo systemctl status nginx | sed -n "1,3p"
    sleep 15
    echo -e "$GREEN Done...$COL_RESET"

    # Making Nginx a bit hard
    echo 'map $http_user_agent $blockedagent {
    default         0;
    ~*malicious     1;
    ~*bot           1;
    ~*backdoor      1;
    ~*crawler       1;
    ~*bandit        1;
    }
    ' | sudo -E tee /etc/nginx/blockuseragents.rules >/dev/null 2>&1

    # Installing Installing php8.2
    echo
    echo
    echo -e "$CYAN => Installing php8.2: $COL_RESET"
    sleep 3

    source conf/pool.conf
    if [ ! -f /etc/apt/sources.list.d/ondrej-php-bionic.list ]; then
    hide_output sudo add-apt-repository -y ppa:ondrej/php
    fi
    hide_output sudo apt -y update

    if [[ ("$DISTRO" == "22") ]]; then
    apt_install php8.2-fpm php8.2-opcache php8.2 php8.2-common php8.2-gd php8.2-mysql php8.2-imap php8.2-cli \
    php8.2-cgi php-pear imagemagick libruby php8.2-curl php8.2-intl php8.2-pspell mcrypt\
    recode php8.2-sqlite3 php8.2-tidy php8.2-xmlrpc php8.2-xsl memcached php-imagick php-php-gettext php8.2-zip php8.2-mbstring \
    libpsl-dev libnghttp2-dev php8.2-memcache php8.2-memcached net-tools
    else  
     echo -e "$RED Aborting, wrong O/S. Must be Ubuntu 22.04."
     exit 1
    fi

    hide_output sudo update-alternatives --set php /usr/bin/php8.2
    
    sleep 5
    hide_output sudo systemctl start php8.2-fpm
    sudo systemctl status php8.2-fpm | sed -n "1,3p"
    sleep 15
    echo -e "$GREEN Done...$COL_RESET"

    # Installing other needed files
    echo
    echo
    echo -e "$CYAN => Installing other required files: $COL_RESET"
    sleep 3

    hide_output sudo apt -y install libgmp3-dev libmysqlclient-dev libcurl4-gnutls-dev libkrb5-dev libldap2-dev libidn11-dev gnutls-dev \
    librtmp-dev sendmail mutt screen git
    hide_output sudo apt -y install pwgen -y
    echo -e "$GREEN Done...$COL_RESET"
    sleep 3

    
    #TODO: Need testing
    # Test Email
    echo
    echo
    echo -e "$CYAN => Testing to see if server emails are sent: $COL_RESET"
    sleep 3

    if [[ "$root_email" != "" ]]; then
        echo $root_email > sudo tee --append ~/.email
        echo $root_email > sudo tee --append ~/.forward

    if [[ ("$send_email" == "y" || "$send_email" == "Y" || "$send_email" == "") ]]; then
        echo "This is a mail test for the SMTP Service." > sudo tee --append /tmp/email.message
        echo "You should receive this !" >> sudo tee --append /tmp/email.message
        echo "" >> sudo tee --append /tmp/email.message
        echo "Cheers" >> sudo tee --append /tmp/email.message
        sudo sendmail -s "SMTP Testing" $root_email < sudo tee --append /tmp/email.message

        hide_output sudo rm -f /tmp/email.message
        echo "Mail sent"
    fi
    fi
    echo -e "$GREEN Done...$COL_RESET"
    
    echo -e "$GREEN Done...$COL_RESET"

    # Creating webserver initial config file
    echo
    echo
    echo -e "$CYAN => Creating webserver initial config file: $COL_RESET"

    # Adding user to group, creating dir structure, setting permissions
    sudo mkdir -p /var/www/$server_name/html

    if [[ ("$sub_domain" == "y" || "$sub_domain" == "Y") ]]; then
    echo 'include /etc/nginx/blockuseragents.rules;
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
        root "/var/www/'"${server_name}"'/html/web";
        index index.html index.htm index.php;
        charset utf-8;

        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }

        location = /favicon.ico { access_log off; log_not_found off; }
        location = /robots.txt  { access_log off; log_not_found off; }

        access_log /var/log/nginx/'"${server_name}"'.app-access.log;
        error_log /var/log/nginx/'"${server_name}"'.app-error.log;

        # allow larger file uploads and longer script runtimes
    client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;

        location ~ ^/index\.php$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_intercept_errors off;
            fastcgi_buffer_size 16k;
            fastcgi_buffers 4 16k;
            fastcgi_connect_timeout 300;
            fastcgi_send_timeout 300;
            fastcgi_read_timeout 300;
        try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
            return 404;
        }
        location ~ \.sh {
        return 404;
        }
        location ~ /\.ht {
        deny all;
        }
        location ~ /.well-known {
        allow all;
        }
		location ^~ /list-algos/ {
		deny all;
			access_log off;
			return 301 https://$server_name;
		}
        location /phpmyadmin {
        root /usr/share/;
        index index.php;
        try_files $uri $uri/ =404;
        location ~ ^/phpmyadmin/(doc|sql|setup)/ {
            deny all;
      }
        location ~ /phpmyadmin/(.+\.php)$ {
            fastcgi_pass unix:/run/php/php8.2-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
            include snippets/fastcgi-php.conf;
        }
      }
    }
    ' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1

    sudo ln -s /etc/nginx/sites-available/$server_name.conf /etc/nginx/sites-enabled/$server_name.conf
    sudo ln -s /var/web /var/www/$server_name/html
    sudo ln -s /var/stratum/config /var/web/list-algos
    hide_output sudo systemctl reload php8.2-fpm.service
    hide_output sudo systemctl restart nginx.service
    echo -e "$GREEN Done...$COL_RESET"

    if [[ ("$ssl_install" == "y" || "$ssl_install" == "Y" || "$ssl_install" == "") ]]; then

    # Install SSL (with SubDomain)
    echo
    echo -e 'Install LetsEncrypt and setting SSL (with SubDomain)'
    echo

    hide_output sudo apt -y install letsencrypt
    hide_output sudo letsencrypt certonly -a webroot --webroot-path=/var/web --email "$EMAIL" --agree-tos -d "$server_name"
    sudo rm /etc/nginx/sites-available/$server_name.conf
    hide_output sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    # I am SSL Man!
    echo 'include /etc/nginx/blockuseragents.rules;
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
        # enforce https
        return 301 https://$server_name$request_uri;
    }

    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
            listen 443 ssl http2;
            listen [::]:443 ssl http2;
            server_name '"${server_name}"';

            root /var/www/'"${server_name}"'/html/web;
            index index.php;

            access_log /var/log/nginx/'"${server_name}"'.app-access.log;
            error_log  /var/log/nginx/'"${server_name}"'.app-error.log;

            # allow larger file uploads and longer script runtimes
    client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;

            # strengthen ssl security
            ssl_certificate /etc/letsencrypt/live/'"${server_name}"'/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/'"${server_name}"'/privkey.pem;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            ssl_prefer_server_ciphers on;
            ssl_session_cache shared:SSL:10m;
            ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
            ssl_dhparam /etc/ssl/certs/dhparam.pem;

            # Add headers to serve security related headers
            add_header Strict-Transport-Security "max-age=15768000; preload;";
            add_header X-Content-Type-Options nosniff;
            add_header X-XSS-Protection "1; mode=block";
            add_header X-Robots-Tag none;
            add_header Content-Security-Policy "frame-ancestors 'self'";

        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }


            location ~ ^/index\.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_intercept_errors off;
                fastcgi_buffer_size 16k;
                fastcgi_buffers 4 16k;
                fastcgi_connect_timeout 300;
                fastcgi_send_timeout 300;
                fastcgi_read_timeout 300;
                include /etc/nginx/fastcgi_params;
            try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
            return 404;
        }
        location ~ \.sh {
        return 404;
        }

            location ~ /\.ht {
                deny all;
            }
        location /phpmyadmin {
        root /usr/share/;
        index index.php;
        try_files $uri $uri/ =404;
        location ~ ^/phpmyadmin/(doc|sql|setup)/ {
            deny all;
    }
        location ~ /phpmyadmin/(.+\.php)$ {
            fastcgi_pass unix:/run/php/php8.2-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
            include snippets/fastcgi-php.conf;
       }
     }
    }

    ' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1
    fi

    hide_output sudo systemctl reload php8.2-fpm.service
    hide_output sudo systemctl restart nginx.service
    echo -e "$GREEN Done...$COL_RESET"

    else
    echo 'include /etc/nginx/blockuseragents.rules;
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"' www.'"${server_name}"';
        root "/var/www/'"${server_name}"'/html/web";
        index index.html index.htm index.php;
        charset utf-8;

        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }

        location = /favicon.ico { access_log off; log_not_found off; }
        location = /robots.txt  { access_log off; log_not_found off; }

        access_log /var/log/nginx/'"${server_name}"'.app-access.log;
        error_log /var/log/nginx/'"${server_name}"'.app-error.log;

        # allow larger file uploads and longer script runtimes
        client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;

        location ~ ^/index\.php$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_intercept_errors off;
            fastcgi_buffer_size 16k;
            fastcgi_buffers 4 16k;
            fastcgi_connect_timeout 300;
            fastcgi_send_timeout 300;
            fastcgi_read_timeout 300;
        try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
            return 404;
        }
        location ~ \.sh {
        return 404;
        }
        location ~ /\.ht {
        deny all;
        }
        location ~ /.well-known {
        allow all;
        }
		location ^~ /list-algos/ {
		deny all;
			access_log off;
			return 301 https://$server_name;
		}
        location /phpmyadmin {
        root /usr/share/;
        index index.php;
        try_files $uri $uri/ =404;
        location ~ ^/phpmyadmin/(doc|sql|setup)/ {
            deny all;
    }
        location ~ /phpmyadmin/(.+\.php)$ {
            fastcgi_pass unix:/run/php/php8.2-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
            include snippets/fastcgi-php.conf;
        }
      }
    }
    ' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1

    sudo ln -s /etc/nginx/sites-available/$server_name.conf /etc/nginx/sites-enabled/$server_name.conf
    sudo ln -s /var/web /var/www/$server_name/html
    sudo ln -s /var/stratum/config /var/web/list-algos
    hide_output sudo systemctl reload php8.2-fpm.service
    hide_output sudo systemctl restart nginx.service
    echo -e "$GREEN Done...$COL_RESET"

    if [[ ("$ssl_install" == "y" || "$ssl_install" == "Y" || "$ssl_install" == "") ]]; then

    # Install SSL (without SubDomain)
    echo
    echo -e 'Install LetsEncrypt and setting SSL (without SubDomain)'
    echo
    sleep 3

    hide_output sudo apt -y install letsencrypt
    hide_output sudo letsencrypt certonly -a webroot --webroot-path=/var/web --email "$EMAIL" --agree-tos -d "$server_name" -d www."$server_name"
    hide_output sudo rm /etc/nginx/sites-available/$server_name.conf
    hide_output sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    # I am SSL Man!
    echo 'include /etc/nginx/blockuseragents.rules;
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
        # enforce https
        return 301 https://$server_name$request_uri;
    }

    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
            listen 443 ssl http2;
            listen [::]:443 ssl http2;
            server_name '"${server_name}"' www.'"${server_name}"';

            root /var/www/'"${server_name}"'/html/web;
            index index.php;

            access_log /var/log/nginx/'"${server_name}"'.app-access.log;
            error_log  /var/log/nginx/'"${server_name}"'.app-error.log;

            # allow larger file uploads and longer script runtimes
        client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;

            # strengthen ssl security
            ssl_certificate /etc/letsencrypt/live/'"${server_name}"'/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/'"${server_name}"'/privkey.pem;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            ssl_prefer_server_ciphers on;
            ssl_session_cache shared:SSL:10m;
            ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
            ssl_dhparam /etc/ssl/certs/dhparam.pem;

            # Add headers to serve security related headers
            add_header Strict-Transport-Security "max-age=15768000; preload;";
            add_header X-Content-Type-Options nosniff;
            add_header X-XSS-Protection "1; mode=block";
            add_header X-Robots-Tag none;
            add_header Content-Security-Policy "frame-ancestors 'self'";

        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }

            location ~ ^/index\.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_intercept_errors off;
                fastcgi_buffer_size 16k;
                fastcgi_buffers 4 16k;
                fastcgi_connect_timeout 300;
                fastcgi_send_timeout 300;
                fastcgi_read_timeout 300;
                include /etc/nginx/fastcgi_params;
            try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
            return 404;
        }
 
		location ~ \.sh {
			return 404;
        }

		location ~ /\.ht {
			deny all;
		}
		
		location /phpmyadmin {
        root /usr/share/;
        index index.php;
        try_files $uri $uri/ =404;
        location ~ ^/phpmyadmin/(doc|sql|setup)/ {
            deny all;
    }
        location ~ /phpmyadmin/(.+\.php)$ {
            fastcgi_pass unix:/run/php/php8.2-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
            include snippets/fastcgi-php.conf;
        }
      }
    }

    ' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1

    echo -e "$GREEN Done...$COL_RESET"

    fi
    hide_output sudo systemctl reload php8.2-fpm.service
    hide_output sudo systemctl restart nginx.service
    fi

   
    whoami=`whoami`
    sudo usermod -aG www-data $whoami
    sudo usermod -a -G www-data $whoami

    sudo find /var/web -type d -exec chmod 775 {} +
    sudo find /var/web -type f -exec chmod 664 {} +
    sudo chgrp www-data /var/web -R
    sudo chmod g+w /var/web -R

    
    #Add to contrab screen-script
    (crontab -l 2>/dev/null; echo "@reboot sleep 20 && /etc/screen-script.sh") | crontab -

    #Add to contrab screen-stratum
    (crontab -l 2>/dev/null; echo "@reboot sleep 20 && /etc/screen-stratum.sh") | crontab -

    #fix error screen main "service"
    sudo sed -i 's/service $webserver start/sudo service $webserver start/g' /var/web/yaamp/modules/thread/CronjobController.php
    sudo sed -i 's/service nginx stop/sudo service nginx stop/g' /var/web/yaamp/modules/thread/CronjobController.php

    sudo mkdir -p /home/crypto-data/wallets
    sudo chown -R ${whoami}:${whoami} /home/crypto-data/

    #fix error screen main "backup sql frontend"
    sudo sed -i "s|/root/backup|/home/crypto-data/backups|g" /var/web/yaamp/core/backend/system.php
    sudo sed -i '14d' /var/web/yaamp/defaultconfig.php

    #MOTD
    sudo rm -r /etc/update-motd.d/
    sudo mkdir /etc/update-motd.d/
    sudo cp yiimp_install_script/conf/motd/* /etc/update-motd.d/
    sudo chmod +x /etc/update-motd.d/*

    if [[ $poolname == "" ]]
    then
       poolname="Saltpool"
    fi
     
    sudo sed -i "s/xxxxxx/$poolname/g" /etc/update-motd.d/00-header
    echo '
    clear
    run-parts /etc/update-motd.d/ | sudo tee /etc/motd
    ' | sudo -E tee /usr/bin/motd >/dev/null 2>&1
    sudo chmod +x /usr/bin/motd
    
    sudo cp yiimp_install_script/utils/screens /usr/bin/
    sudo chmod +x /usr/bin/screens 

    #Donations
    echo 'BTCDON="16uNjqH5yqY4JaMTHtzddAHP2PfXYTGjhV"
    LTCDON="LYB73E44CvijJXXCT1vEYYcnJstaKNriWv"
    ETHDON="0x250e5d18fD7Fe2FaF8aD0c8221A889B9bc048076"
    DOGEDON="D9tm4GDjmFHtNBUU47aRYxiKeDWnNGbLVQ"' | sudo -E tee /etc/yiimpdonate.conf >/dev/null 2>&1

    #Misc
    sudo mv $HOME/yiimp/ $HOME/yiimp-install-only-do-not-run-commands-from-this-folder
    sudo rm -rf /var/log/nginx/*

    #Hold update OpenSSL
    #If you want remove the hold: sudo apt-mark unhold openssl
    hide_output sudo apt-mark hold openssl

    #Restart service
    hide_output sudo systemctl restart cron.service
    hide_output sudo systemctl restart mysql
    sudo systemctl status mysql | sed -n "1,3p"
    hide_output sudo systemctl restart nginx.service
    sudo systemctl status nginx | sed -n "1,3p"
    hide_output sudo systemctl restart php8.2-fpm.service
    sudo systemctl status php8.2-fpm | sed -n "1,3p"

    echo -e "$GREEN Done...$COL_RESET"
    sleep 3

    sudo sed -i 's/$nrconf{restart} = '"'"'a'"'"';/#$nrconf{restart} = '"'"'i'"'"';/g' /etc/needrestart/needrestart.conf

    echo
    echo -e "$GREEN***************************************************$COL_RESET"
    echo -e "$GREEN Yiimp Install Script $script_version $COL_RESET"
    echo -e "$GREEN Finished !!! $COL_RESET"
    echo -e "$GREEN***************************************************$COL_RESET"
    echo
    echo -e "$YELLOW REMINDERS: $COL_RESET"
    echo -e "$CYAN \e[1mYour mysql information has been saved in ~/.my.cnf. $COL_RESET"
    echo
    echo -e "$CYAN Yiimp at: http://$server_name (https... if SSL enabled)"
    echo -e "$CYAN \e[1mYiimp Admin at: http://$server_name/site/$admin_panel (https... if SSL enabled)"
    echo -e "$CYAN Yiimp phpMyAdmin at: http://$server_name/phpmyadmin (https... if SSL enabled)"
    echo
    echo -e "$CYAN If you want change $admin_panel to access Panel Admin, edit this file: /var/web/yaamp/modules/site/SiteController.php"
    echo -e "$CYAN Line 11 => change $admin_panel and use the new access name"
    echo
    echo -e "$GREEN Please make sure to change your public keys/wallet addresses in the /var/web/serverconfig.php file. $COL_RESET"
    echo -e "$GREEN Please make sure to change your private keys in the /etc/yiimp/keys.php file. $COL_RESET"
    echo
    echo -e "$YELLOW***************************************************$COL_RESET"
    echo -e "$YELLOW \e[1mYOU MUST REBOOT NOW TO FINALISE INSTALLATION !!!  $COL_RESET"
    echo -e "$YELLOW***************************************************$COL_RESET"
    echo -e "$YELLOW If you have a white/blank page on the site check       $COL_RESET"
    echo -e "$YELLOW php$php_version-memcache | php$php_version-memcached | php$php_version-fpm   $COL_RESET"
    echo -e "$YELLOW Try to restart them, or install if they don't exist.                    $COL_RESET"
    echo -e "$YELLOW***************************************************$COL_RESET"
    echo
