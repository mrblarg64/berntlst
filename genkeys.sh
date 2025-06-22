#!/bin/bash
rm server.key server.pem client.key client.pem
certtool --generate-privkey --bits=8192 --outfile server.key --rsa
certtool --generate-self-signed --load-privkey server.key --outfile server.pem
certtool --generate-privkey --bits=8192 --outfile client.key --rsa
certtool --generate-self-signed --load-privkey client.key --outfile client.pem
