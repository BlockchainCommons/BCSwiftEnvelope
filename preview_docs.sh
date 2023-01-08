#!/bin/bash

DOCS_PATH=${PWD}/docs
TARGET=Envelope
HOST_BASE_PATH=BCSwiftEnvelope

cd docs
python3 -m http.server 7800
