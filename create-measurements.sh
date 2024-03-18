#!/bin/bash
set -x
pushd 1brc-java
./mvnw clean verify
./create_measurements.sh $*
popd
ln -s 1brc-java/measurements.txt ./
