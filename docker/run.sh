#!/bin/bash
set -ex

cp $1 ../docker/test_docker/bin/pwn

cd ../docker/test_docker
echo "yuge" |sudo -S docker ps -f "name = test_docker" | grep "test_docker" && echo "yuge" |sudo -S docker rm -f test_docker
echo "yuge" |sudo -S docker build -t "test_docker" .
echo "yuge" |sudo -S docker run -d -p "0.0.0.0:$2:9999" -h "test_docker" --name="test_docker" test_docker
