# CertificateCheck
Small repo with InfoSec Code for the checking and control of certificate protected end points.

### N3 ITK Endpoint Certificate test
Script to be run on an N3 connected machine that takes a txt file list of the one one one ITK endpoint domains and attempts to initiate an SSL connection to them.    

text file content example :
  * https://odscode1.oneoneone.nhs.uk:1880
  * https://odscode2.oneoneone.nhs.uk:1880/NHS111Reportv20.svc
  * https://odscode3.oneoneone.nhs.uk/NHS111/

It captures the x509 cert offered by the endpoint and checks the expiry date of that endpoint

###Dave Pollard, Information Security SME

## Requirements

Written in Python 3 and expects the following standard python modules
      * os, csv, datetime, socket 

Due to issues with the standard OpenSSL libraries,  requires the use of pyOpenSSL installed with pip3 (to resolve dependancies and issues with local SSL implementations) 

Recommended :
   *  Pip version 8.0.3 or above
    * pyOpenSSL-0.15.1 or above

To install PIP
    * sudo easy_install install pip 
  -or-
    * sudo easy_install update pip 

To install pyOpenSSL
    * pip install pyOpenSSL


