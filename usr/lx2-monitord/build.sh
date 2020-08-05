#!/bin/bash

set -ex

pushd /home/jimcoggeshall/usr/lx2-monitord
wget -N https://iptoasn.com/data/ip2asn-v4.tsv.gz
zcat ip2asn-v4.tsv.gz > ip2asn-v4.tsv
docker build -t lx2-monitord .
popd
