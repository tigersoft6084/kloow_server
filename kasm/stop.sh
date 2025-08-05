docker stop $1
docker rm $1

#docker rm -f $(docker ps -a -q)