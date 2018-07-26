#!/usr/bin/env bash

export DIR=`dirname $(readlink -f $0)`
mkdir -p $DIR/.certs
cd $DIR/.certs

## Generate private key
export PASSWORD='pass:p@$$wo!d'
export TIMESTAMP="$(date -Isecond)"
export PRI_KEY="isv_$TIMESTAMP.key"
find isv_*.key > /dev/null 2>&1 \
&& PRI_KEY="$(find isv_*.key 2>/dev/null|head -n 1)" \
|| openssl genrsa -out "$PRI_KEY" -des3 -passout "$PASSWORD" 2048

## Generate self-signed CA certificate
test -e ca.crt || openssl req -new -x509 -days 3650 \
-key $PRI_KEY -out ca.crt -passin "$PASSWORD" \
-subj "/C=ph/ST=ncr/L=makati/O=sme/OU=r&d/CN=*.smeinternet.com"

## Generate certificate for consumer
#export DEMO="demo_$TIMESTAMP"
export DEMO="consumer"
if [ ! -e "$DEMO.crt" ]; then
  openssl req -new -key $PRI_KEY -passin "$PASSWORD" -out "$DEMO.csr" -subj "/C=ph/ST=ncr/L=pasay/O=haocai/OU=it/CN=*.haocai.com"
  openssl x509 -req -in "$DEMO.csr" -days 7 -CA ca.crt -CAkey "$PRI_KEY" -passin "$PASSWORD" -CAcreateserial -out "$DEMO.crt"
  faketime '2017-01-01 12:00:00' openssl x509 -req -in "$DEMO.csr" -days 7 -CA ca.crt -CAkey "$PRI_KEY" -passin "$PASSWORD" -CAcreateserial -out "$DEMO""_expired.crt"
fi

## Copy ca.crt pem text to java code
cd ..
test -z "$(find -name CertVerficationHelper.java)" && exit 0
JAVA=$(find -name CertVerficationHelper.java)
LN=`cat "$JAVA" | grep -n -e 'BEGIN CERT' -e 'END CERT' | awk '{print $1}' FS=':'`
LN_1=$(echo $LN|awk '{print $1}')
LN_2=$(echo $LN|awk '{print $2}')

echo -n > /tmp/ca.crt.snippet
while read line
do
  if [[ $line = *"END CERT"* ]]; then
    echo "\"$line\"" >> /tmp/ca.crt.snippet
  else
    echo "\"$line\\n\" +" >> /tmp/ca.crt.snippet
  fi
done < .certs/ca.crt

cat "$JAVA"|sed -e "$LN_1,$LN_2""d" -e "$((LN_1-1))r /tmp/ca.crt.snippet" > "$JAVA"".tmp"
mv "$JAVA"".tmp" "$JAVA"

## Copy consumer's certificate to resource directory
cp .certs/$DEMO.crt src/main/resources
cp .certs/"$DEMO""_expired.crt" src/main/resources