#!/usr/bin/env bash
#
# Build all the debian packages and the windows installer using docker
set -ex

function build() {
	docker build -t $1 . --build-arg target=$1
	CONTAINER_ID=$(docker create $1)
	rm -rf ./$1
	docker cp $CONTAINER_ID:/home/stonenet/out ./$1
	docker rm $CONTAINER_ID
}

build amd64
build arm64
build win64
