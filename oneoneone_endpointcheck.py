#!/Library/Frameworks/Python.framework/Versions/3.4/bin/python3
#-------------------------------------------------------------------------------
# v2.0 3 March 2016
#
# Script to be run on an N3 connected machine that takes a txt file list of
# the one one one ITK endpoint domains and attempts to initiate an SSL
# connection to them.    It captures the x509 cert offered by the endpoint and
# checks the expiry date of that endpoint
# 
# Dave Pollard, Security SME,  NHS 111 Online Programme
#-------------------------------------------------------------------------------
import os
import csv
import glob
from datetime import datetime
from OpenSSL import SSL
from socket import socket

# Get the list of endpoints from DOS
DOS_Extract_File = "111_Endpoints.txt"
DOS_EndPoints = []
with open(DOS_Extract_File) as DOS_Extract:
    lines = DOS_Extract.read().splitlines()
    for line in lines:
        DOSFields = line.split('/')
        DOS_URI = DOSFields[2]
        DOS_EndPoints.append(DOS_URI)
# Strip out the duplicates
Unique_EndPoints = set(DOS_EndPoints)
# Step through all the known endpoints
for EndPoint in sorted(Unique_EndPoints):
    # Parse the Endpoint to determine domain and port numbers
    EndPointFields = EndPoint.split(":",1)
    if len(EndPointFields)> 1 :
        hostname = EndPointFields[0]
        port = int(EndPointFields[1])
    else :
        hostname = EndPoint
        port = 443
    # Create a context that a connection can use
    # context = SSL.Context(SSL.TLSv1_METHOD) # Use TLS Method
    context = SSL.Context(SSL.TLSv1_2_METHOD) # Use TLS1.2 Method only 
    context.set_options(SSL.OP_NO_SSLv2) # Don't accept SSLv2
    context.set_options(SSL.OP_NO_SSLv3) # Don't accept SSLv3
    # create an SSL Connection, timeout before for connect, not once connected
    sock = socket()
    ssl_sock = SSL.Connection(context, sock)
    ssl_sock.settimeout(10)
    try :
        ssl_sock.connect((hostname, port))
        # Set no timeout as we need explicit response
        ssl_sock.settimeout(None)
        ssl_sock.do_handshake()
        # Get the presented cert ( a x509 object )
        cert = ssl_sock.get_peer_certificate()
        # Get the required fields from the cert
        common_name = cert.get_subject().commonName
        certIssuer = cert.get_issuer().commonName
        certAlgor = cert.get_signature_algorithm().decode("utf-8")
        expirydate = cert.get_notAfter().decode("utf-8")
    except : 
        expirydate = "20000101120000Z"
    dt_obj = datetime.strptime(expirydate, "%Y%m%d%H%M%SZ")
    expirydate = dt_obj.strftime("%Y-%m-%d %H:%M:%S")   
    # Need to sort out the output aspect for script here
    print(hostname, port, expirydate)
'''
################################################################################
 Define the procs, subs and stuff below here 
################################################################################
'''    
# Format the output 

  

    
# callback to verify the cert return.
'''
Can be expanded out more at a later date if further cert chain checks
are required. 
'''
def callback(conn, cert, errno, depth, result):
    if depth == 0 and (errno == 9 or errno == 10):
        return False # or raise Exception("Certificate not yet valid or expired")
    return True
