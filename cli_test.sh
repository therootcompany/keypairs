#!/bin/bash
set -u

go build -mod=vendor cmd/keypairs/*.go
./keypairs gen > testkey.jwk.json 2> testpub.jwk.json

./keypairs sign --exp 1h ./testkey.jwk.json '{"foo":"bar"}' > testjwt.txt 2> testjws.json

echo ""
echo "Should pass:"
./keypairs verify ./testpub.jwk.json testjwt.txt > /dev/null
./keypairs verify ./testpub.jwk.json "$(cat testjwt.txt)" > /dev/null
./keypairs verify ./testpub.jwk.json testjws.json > /dev/null
./keypairs verify ./testpub.jwk.json "$(cat testjws.json)" > /dev/null

echo ""
echo "Should fail:"
./keypairs sign --exp -1m ./testkey.jwk.json '{"bar":"foo"}' > errjwt.txt 2> errjws.json
./keypairs verify ./testpub.jwk.json errjwt.txt > /dev/null
