#!/bin/bash

set -ex

pushd $HOME/usr/lx2-jupyterlab
docker build -t lx2-jupyterlab .
popd
