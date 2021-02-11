#!/bin/sh
docker build . -f Dockerfile -t fuzzilli:latest 
docker run -it fuzzilli:latest