#!/usr/bin/env bash
# Build all the debian packages and the windows installer using docker
set -ex


function build() {
	docker build -t $2 . --build-arg target=$2
	CONTAINER_ID=$(docker create $2)
	rm -rf ./$1/$2
	docker cp $CONTAINER_ID:/home/stonenet/out ./out/$1/$2
	docker rm $CONTAINER_ID
}


rm -rf ./out
mkdir -p ./out/{debian,windows}
build debian amd64
build debian arm64
build debian armhf
build windows win64
