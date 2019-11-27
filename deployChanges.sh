#!/bin/bash

unzip -o totpauth-impl/target/totpauth-impl-1.0-bin.zip
yes | cp -R ./totpauth-impl-1.0/* /opt/shibboleth-idp/
/opt/shibboleth-idp/bin/build.sh
deployIDP.py shibboleth-idp_11082019

