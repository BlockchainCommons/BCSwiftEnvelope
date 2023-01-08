#!/bin/zsh

rm -rf docs
rm -rf docs_source

find ~/Library/Developer/Xcode/DerivedData \
    -name "Envelope.doccarchive" \
    -exec rm -Rf {} \; || true

xcodebuild \
    -scheme Envelope \
    -destination 'generic/platform=ios'

xcodebuild docbuild \
    -scheme Envelope \
    -destination 'generic/platform=ios'

find ~/Library/Developer/Xcode/DerivedData \
    -name "Envelope.doccarchive" \
    -exec cp -R {} docs_source \;

$(xcrun --find docc) process-archive \
    transform-for-static-hosting docs_source \
    --hosting-base-path /BCSwiftEnvelope \
    --output-path docs

rm -rf docs_source
