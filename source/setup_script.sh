#!/bin/bash

# Generate server key pair
openssl genrsa -out server.key

# Generate user key pair
openssl genrsa -out user.key

# Generate database key pair
openssl genrsa -out db.key

# Create Certificate Signing Request for server
openssl req -new -key server.key -out server.csr

# Create Certificate Signing Request for user
openssl req -new -key user.key -out user.csr

# Create Certificate Signing Request for database
openssl req -new -key db.key -out db.csr

# Self-sign server certificate
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt -extfile webserver.ext

# Create the server database
echo 01 > server.srl

# Sign user certificate with the server
openssl x509 -req -days 365 -in user.csr -CA server.crt -CAkey server.key -out user.crt 

# Sign database certificate with the server
openssl x509 -req -days 365 -in db.csr -CA server.crt -CAkey server.key -out db.crt -extfile db.ext

# Convert certificates to PEM format
openssl x509 -in server.crt -out server.pem
openssl x509 -in user.crt -out user.pem
openssl x509 -in db.crt -out db.pem

# Create a p12 file for the server
openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12 -password pass:changeme

# Create a p12 file for the user
openssl pkcs12 -export -in user.crt -inkey user.key -out user.p12 -password pass:changeme

# Create a p12 file for the database
openssl pkcs12 -export -in db.crt -inkey db.key -out db.p12 -password pass:changeme

# Import user certificate into the server keystore

keytool -import -trustcacerts -alias user_cert -file user.pem -storepass changeme -keypass changeme -keystore servertruststore.jks

keytool -import -trustcacerts -file server.pem -storepass changeme -keypass changeme -keystore usertruststore.jks 

# Import database certificate into the server keystore

keytool -import -trustcacerts -file db.pem -storepass changeme -keypass changeme -keystore servertruststore.jks 