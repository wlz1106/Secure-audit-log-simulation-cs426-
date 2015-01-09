#!/bin/bash

openssl genrsa -out privateKeyT.pem 1024
openssl rsa -in privateKeyT.pem -pubout -out publicKeyT.pem

openssl genrsa -out privateKeyU.pem 1024
openssl rsa -in privateKeyU.pem -pubout -out publicKeyU.pem

openssl req -new -key privateKeyT.pem -out certificateU.csr
openssl x509 -req -days 128 -in certificateU.csr -signkey privateKeyT.pem -out certificateU.crt

