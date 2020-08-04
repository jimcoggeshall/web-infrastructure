#!/bin/bash

set -ex

pushd /home/jimcoggeshall/usr/lx2-monitord
docker build -t lx2-monitord .
popd
