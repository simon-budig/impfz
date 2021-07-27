#!/usr/bin/env python3

import sys, os
import urllib.request

import base45
import zlib
import cbor
import cose.messages
import cose.headers

import json
import base64
import cryptography

certificates = {}

def load_certificates (filename="dsc-list.json"):
   global certificates

   if not os.path.exists (filename):
      urllib.request.urlretrieve ("https://de.dscg.ubirch.com/trustList/DSC/",
                                  filename)

   infile = open (filename)

   # first line contains signature data, we don't use it
   discard = infile.readline ()

   cdata = infile.read ()
   certs = json.loads (cdata)["certificates"]
   for c in certs:
      certificates [base64.b64decode (c["kid"])] = c


if __name__ == '__main__':
   load_certificates ()

   for name in sys.argv[1:]:
      b54_data = open (name).read ()
      if b54_data[:4] != "HC1:":
         print (f"{name} is not a valid certificate scan",
                file=sys.stderr)
         continue

      try:
         z_data = base45.b45decode (b54_data[4:])
      except ValueError:
         print (f"{name} does not contain base45 encoded data",
                file=sys.stderr)
         continue

      try:
         raw_data = zlib.decompress (z_data)
      except zlib.error:
         print (f"{name} does not contain zlib encoded data",
                file=sys.stderr)
         continue

      co = cose.messages.Sign1Message.decode (raw_data)

      key_id = co.get_attr (cose.headers.KID)
      payload = cbor.loads (co.payload)
      raw_cert = base64.b64decode (certificates [key_id]["rawData"])
      cert = cryptography.x509.load_der_x509_certificate (raw_cert)

      print ("key-id:", key_id.hex())
      print ("Cert-Subject:", cert.subject)
      print ("ci:", payload[-260][1]["v"][0]["ci"])
      print ("Name:", payload[-260][1]["nam"]["fn"])
      print ("Vorname:", payload[-260][1]["nam"]["gn"])
      print ("Geburtstag:", payload[-260][1]["dob"])

      pubnums = cert.public_key().public_numbers()
      key = cose.keys.ec2.EC2Key (cose.keys.curves.P256,
                                  x = pubnums.x.to_bytes (32, 'big'),
                                  y = pubnums.y.to_bytes (32, 'big'))
      co.key = key
      print ("Verified:", co.verify_signature())
      print ()

   if len (sys.argv) < 2:
      for key_id in certificates:
         raw_cert = base64.b64decode (certificates [key_id]["rawData"])
         cert = cryptography.x509.load_der_x509_certificate (raw_cert)
         print ("key-id:", key_id.hex())
         print ("Cert-Subject:", cert.subject)
         print ()
