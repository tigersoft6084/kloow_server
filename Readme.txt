pm2 start admin_server.js > admin.log 2>&1 &
pm2 start user_server.js > user.log 2>&1 &

pm2 save
pm2 startup

pm2 logs
pm2 list