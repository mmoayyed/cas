#!/bin/bash

# while sleep 9m; do echo -e '\n=====[ Gradle build is still running ]====='; done &

echo "Running midPoint docker container..."
docker stop midpoint-server || true && docker rm midpoint-server || true
docker run -d --rm -p 18181:8080 --name midpoint-server evolveum/midpoint
docker logs -f midpoint-server &
sleep 45
docker ps | grep "midpoint-server"
retVal=$?
if [ $retVal == 0 ]; then
    echo "midPoint docker container is running."
else
    echo "midPoint docker container failed to start."
fi
exit $retVal

