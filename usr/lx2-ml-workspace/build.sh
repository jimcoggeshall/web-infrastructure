#!/bin/bash

set -ex

pushd $HOME/usr/lx2-ml-workspace
docker build -t lx2-ml-workspace .
popd
