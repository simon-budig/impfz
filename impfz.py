#!/usr/bin/env python3

import sys, pprint

import base45
import zlib
import cbor
import cose.messages
import cose.headers

import json
import base64
import OpenSSL

certificates = {}

def load_certificates (filename="dsc-list.json"):
   global certificates

   infile = open (filename)
   discard = infile.readline ()   # not sure what this base64 encoded data is supposed to be
   cdata = infile.read()
   certs = json.loads (cdata)["certificates"]
   for c in certs:
      certificates [base64.b64decode (c["kid"])] = c


if __name__ == '__main__':
   for name in sys.argv[1:]:
      b54_data = open (name).read ()
      if b54_data[:4] != "HC1:":
         print (f"{name} is not a valid certificate scan", file=sys.stderr)
         continue

      try:
         z_data = base45.b45decode (b54_data[4:])
      except ValueError:
         print (f"{name} does not contain base45 encoded data", file=sys.stderr)
         continue

      try:
         raw_data = zlib.decompress (z_data)
      except zlib.error:
         print (f"{name} does not contain zlib encoded data", file=sys.stderr)
         continue

      co = cose.messages.Sign1Message.decode (raw_data)

      key_id = co.get_attr(cose.headers.KID)
      payload = cbor.loads (co.payload)

      print ("key-id:", key_id.hex())
      print ("ci:", payload[-260][1]["v"][0]["ci"])
      print ("Name:", payload[-260][1]["nam"]["fn"])
      print ("Vorname:", payload[-260][1]["nam"]["gn"])
      print ("Geburtstag:", payload[-260][1]["dob"])

      load_certificates ()

      raw_cert = base64.b64decode (certificates [key_id]["rawData"])
      cert = OpenSSL.crypto.load_certificate (OpenSSL.crypto.FILETYPE_ASN1, raw_cert)
      pubnums = cert.get_pubkey().to_cryptography_key().public_numbers()
      key = cose.keys.ec2.EC2Key (cose.keys.curves.P256,
                                  x = pubnums.x.to_bytes (32, 'big'),
                                  y = pubnums.y.to_bytes (32, 'big'))
      co.key = key
      print ("Verified:", co.verify_signature())
      print ()
