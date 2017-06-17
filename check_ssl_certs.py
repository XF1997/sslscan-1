#!/usr/bin/env python3
" look in cachedir, examine each *.pem file, report "
# will eventually become index.cgi
import datetime
import os
import re
import sys
import OpenSSL
import OpenSSL.crypto

SOON = 30  # if cert expires in 30 days, warn.
CACHEDIR = "cache"
HTML_HEAD = """
<head>
<meta charset=utf8>
<link rel=stylesheet type=text/css href=/meter.css >
<style type=text/css>
table { padding:1em; margin:0; border-spacing:0; width:64em;
  border-collapse:collapse; background:white;
  font-size:10pt; font-family:Helvetica, Arial, sans-serif;
  }
td { padding: 0.5em 1em 0.5em 1em; border-left:1px solid white; white-space:nowrap;}
td {vertical-align:top;}
th { color:white; background-color:#3333cc; font-weight:normal;}
tr:nth-child(odd) { background-color:#ccccdd; }
tr:nth-child(even) { background-color:#eeeeff; }
.when {text-align:center; font-style:italic; }
</style>
</head>
<body>
<div id=navbar><a href='/'>Spafax Montreal</a> :: SSLscan</div>
<h1>SSLscan</h1>
<p>Status report of the SSL certs that we watch</p>
<table><tr>
<th>where</th>
<th>name(s) on cert</th>
<th>start</th>
<th>expires</th>
<th>issuer</th>
<th>checked</th>
</tr>"""
HTML_FOOT = """</table></body>"""
VERBOSE = sys.stdin.isatty()


# --
def get_pem_files(where=CACHEDIR):
  return [where + os.sep + i for i in os.listdir(where) if i.endswith('.pem')]


def timedelta_to_nice(td):
  "timedelta to a human-friendly string"
  spans = (('y', 86400 * 365), ('m', 86400 * 30), ('d', 86400), ('h', 3600), ('m', 60), ('s', 1))
  answer = []
  duration = int(td.total_seconds())
  for suff, size in spans:
    if duration > size:
      n, _ = divmod(duration, size)
      answer.append("{}{}".format(n, suff))
      duration -= n * size
  return ', '.join(answer[:1])


def get_cert_hostnames(cert):
  # because the ssl.* don't let me load a PEM from a string, only a living socket
  # and X509 doesn't have a .match_hostname() nor checks extensions.
  names = [cert.get_subject().CN.lower()]
  for i in range(cert.get_extension_count()):
    if cert.get_extension(i).get_short_name() == b'subjectAltName':
      # holy hell this is a hack but how else am I supposed to do this?
      for j in cert.get_extension(i).get_data().split(b'\x82')[1:]:
        names.append(j[1:].decode('utf8').lower())
  return sorted(list(set(names)))  # cheap unique-ifier


def check_cert_has_hostname(cert, hname):
  " is hname in cert subject CN or any of the X509 extensions? "
  # because the ssl.* don't let me load a PEM from a string, only a living socket
  # and X509 doesn't have a .match_hostname() nor checks extensions.
  hname = hname.lower()
  for vname in get_cert_hostnames(cert):
    vname = '^' + vname.replace('*', '.+?') + '$'
    # is there a better way to do glob matching of strings (NOT filenames) ?
    if re.match(vname, hname):
      return True
  return False


def check_cert_issuer(cert):
  " is issuer on a blacklist? "
  # TODO: we SHOULD be using a whitelist instead.
  notary = cert.get_issuer().CN
  if re.match(r'BadSSL ', notary):
    return False
  return True


def spew_pem_status_html(fname):
  hostname = re.sub(r'^' + CACHEDIR + os.sep, '', fname)
  hostname = re.sub(r'(:\d+)?\.pem$', '', hostname)
  print("<tr><td><a href=showcert.cgi?{}>{}</a></td>".format(hostname, hostname))
  crypto = OpenSSL.crypto
  now = datetime.datetime.utcnow()
  try:
    with open(pemfile, 'rt') as i:
      cert = crypto.load_certificate(crypto.FILETYPE_PEM, i.read())
    if cert:
      cn = '<br>'.join(get_cert_hostnames(cert))
      c = '' if (check_cert_has_hostname(cert, hostname)) else ' class=crit'
      print("<td{}>{}</td>".format(c, cn))

      # TODO: warn if start hasn't happend yet
      start = datetime.datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
      c = '' if (start < now) else ' class=crit'
      print("<td{}>{}</td>".format(c, start.date()))

      expiry = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
      c = ''
      if ((expiry - now).days < 30):
        c = ' class=warn'
      if (expiry < now):
        c = ' class=crit'
      # TODO: warn if expiry is soon,
      print("<td{}>{}</td>".format(c, expiry.date()))

      c = '' if (check_cert_issuer(cert)) else ' class=crit'
      print("<td{}>{}</td>".format(c, cert.get_issuer().CN))

  except Exception as err:
    print("<td class=warn colspan=4>could not parse cert file: {}</td>".format(err))
  now = datetime.datetime.now()  # localtime
  ago = now - datetime.datetime.fromtimestamp(os.stat(fname).st_mtime)
  c = '' if (ago.days < 30) else ' class=warn'
  print("<td{}>{} ago</td>".format(c, timedelta_to_nice(ago)))
  print("</tr>")
  print("\n")


# --
if 'REQUEST_METHOD' in os.environ:
  # we're running as a CGI script
  print("Content-Type: text/html;charset=utf8\n\n<!doctype html>")
  print(HTML_HEAD)
  for pemfile in sorted(get_pem_files(CACHEDIR)):
    spew_pem_status_html(pemfile)
  print(HTML_FOOT)
else:
  # we're running command line or cronjob
  raise NotImplementedError
