# SAML
Microservice that provides the ability to create a SAML assertion and validate a SAML assertion.

## Overview
Overview of the SAML endpoints can be accessed below

## Setup

###Set Up the Certificates:

####Generate the private.pem key:
`openssl genpkey -out rsakey.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048`
use this to genrate only rsa key: `openssl genrsa -out private.pem 2048`

####Generate the public.pem key:
`openssl rsa -in private.pem -outform PEM -pubout -out public.pem`

####Create a CSR (Certificate Signing Request) certificate.csr:
`openssl req -new -key private.pem -out certificate.csr`

####Create a self-signed certificate.crt:
`openssl x509 -req -days 3650 -in certificate.csr -signkey private.pem -out certificate.crt`

This certificate.crt is a self-signed certificate which can be safely shared with others.

## Postman

https://www.getpostman.com/collections/1eb67a70024641555b0f

