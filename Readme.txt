pm2 start admin_server.js > admin.log 2>&1 &
pm2 start user_server.js > user.log 2>&1 &

pm2 save
pm2 startup

pm2 logs
pm2 list


sudo nano /etc/nginx/sites-available/kloow.com   # edit config
sudo nginx -t                                    # check for syntax errors
sudo systemctl restart nginx                     # restart nginx

docker exec -it -u root 69de bash


docker exec -it 51c05048e8ff bash


openssl x509 -in ssl.crt -text -noout

docker stop $(docker ps -q)
docker rm -f $(docker ps -a -q)
