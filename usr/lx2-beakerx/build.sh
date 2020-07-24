#!/bin/bash

set -ex

pushd $HOME/usr/lx2-beakerx
docker build -t lx2-beakerx .
popd
