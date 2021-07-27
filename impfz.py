#!/usr/bin/env python3

import sys, pprint

import base45
import zlib
import cbor

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

      cb = cbor.loads (raw_data)

      protected   = cbor.loads (cb.value[0])
      unprotected = cb.value[1]
      payload_cb  = cb.value[2]
      signature   = cb.value[3]

      key_id = unprotected[4]
      payload = cbor.loads (payload_cb)

      print ("key-id:", key_id.hex())
      print ("ci:", payload[-260][1]["v"][0]["ci"])
      print ("Name:", payload[-260][1]["nam"]["fn"])
      print ("Vorname:", payload[-260][1]["nam"]["gn"])
      print ("Geburtstag:", payload[-260][1]["dob"])

      load_certificates ()

      raw_cert = base64.b64decode (certificates [key_id]["rawData"])

      cert = OpenSSL.crypto.load_certificate (OpenSSL.crypto.FILETYPE_ASN1, raw_cert)
      print (OpenSSL.crypto.dump_certificate (OpenSSL.crypto.FILETYPE_TEXT, cert).decode ('utf-8'))
