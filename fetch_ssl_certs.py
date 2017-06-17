#!/usr/bin/env python3
" just grab copies of each SSL certificate "
# TODO: more comand-line switches
# TODO: report. ☉ or ☑ for okay, ⛛ or ⚠ for warn, ☒ or ⛔  for bad
#   see http://shapecatcher.com/unicode/block/Miscellaneous_Symbols
import argparse
import datetime
import filecmp
import OpenSSL.crypto
import os
import os.path
import socket
import ssl
import sys

# see https://badssl.com/ for testing

# don't use ssl.get_server_certificate(), it can return None
#  if it doesn't like the cert it gets.  We _want_ to fetch a bad cert
#  so a human can determine _why_ it is a bad cert.

# ... or I could've just used
# H=expired.badssl.com ; P=443
# openssl s_client -servername $H -connect $H:$P </dev/null 2>/dev/null \
#   |sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' \
#   > $CACHEDIR/$H.pem

# -- config
HEREDIR = (os.path.dirname(sys.argv[0]) or '.')
CACHEDIR = HEREDIR + os.sep + 'cache'
CFGFILE = HEREDIR + os.sep + 'sslscan.cfg'

# ---


def bark(msg):
  if VERBOSE:
    print(msg)


def load_config(cfgfile):
  " return dict of config settings "
  # TODO: more config settings
  answer = {'sitelist': []}
  with open(cfgfile) as fh:
    for line in fh.readlines():
      line = line.rsplit('#', 1)[0].rstrip()
      if not line:
        continue
      answer['sitelist'].append(line)
  return answer


def certfetch_into_cache(sitename, force=False):
  " expects either 'hostname' or 'hostname:portnum' "
  global CACHEDIR
  if os.path.sep in sitename:
    raise TypeError("bad hostname \"{}\"".format(sitename))
  if ':' in sitename:
    hostname, port = sitename.split(':', 1)
    port = int(port)
  else:
    hostname, port = sitename, 443
  certname = CACHEDIR + os.path.sep + sitename + '.pem'
  certname = certname.replace(':', '.')
  tmpname = certname + ".tmp"
  cert = None
  try:
    # cert = ssl.get_server_certificate((hostname, port))   # doesn't do SNI
    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.connect((hostname, port))
    cert = conn.getpeercert(binary_form=True)
    # cert is a DER-encoded blob
    cert = ssl.DER_cert_to_PEM_cert(cert)
    # cert is now a PEM-encoded ascii string
  except Exception as err:
    print("* {} failed: {}".format(sitename, err), file=sys.stderr)
  if not cert:
    # try the method that doesn't do SNI
    try:
      cert = ssl.get_server_certificate((hostname, port))   # doesn't do SNI
    except Exception as err:
      print("* {} failed: {}".format(sitename, err), file=sys.stderr)
  if cert:
    with open(tmpname, 'wb') as tmpfile:
      tmpfile.write(bytes(cert, 'ascii'))
    if force or (not os.path.exists(certname)):
      bark("... " + site + " updated")
      os.rename(tmpname, certname)
    elif filecmp.cmp(certname, tmpname):
      os.remove(tmpname)
    else:
      bark("... " + site + " updated")
      os.rename(tmpname, certname)
  return cert


def spew_cert_warnings(name, cert):
  " print() if ther's something we don't like about cert "
  if isinstance(cert, (bytes, str)):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
  now = datetime.datetime.utcnow()
  expiry = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
  if (expiry <= now):
    print("{}: expired on {}".format(name, expiry))
  elif ((expiry - now).days < 30):
    print("{}: expires on {}".format(name, expiry))


def build_argparser():
  i = argparse.ArgumentParser()
  i.add_argument('-v', help="verbose output", action="store_true", default=sys.stdin.isatty())
  i.add_argument('-f', '--force', help="force fetching fresh", action="store_true", default=False)
  i.add_argument('-w', '--warn', help="complain about certs expiring", action="store_true", default=False)
  j = i.add_mutually_exclusive_group()
  j.add_argument('-a', help="all built-in hostnames", action="store_true", default="False")
  j.add_argument('hostnames', metavar='hostname', help="hostnames to check", nargs="*", default=[])
  return i

# --

ARGPAR = build_argparser()
ARGS = ARGPAR.parse_args()
CONFIG = load_config(CFGFILE)

VERBOSE = ARGS.v
if ARGS.a:
  bark("... using default list of sites")
  sitelist = CONFIG['sitelist']
elif ARGS.hostnames:
  sitelist = ARGS.hostnames
else:
  ARGPAR.print_help()
  sys.exit(1)

for site in sitelist:
  cert = certfetch_into_cache(site, ARGS.force)
  if not cert:
    print("* failed to get cert for {}".format(site))
    continue
  if ARGS.warn:
    spew_cert_warnings(site, cert)
