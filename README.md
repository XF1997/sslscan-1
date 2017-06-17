sslscan
=====
Simple SSL cert monitoring and report.

I need something reliable that will report when SSL certs will expire,
did expire, are mismatched, or are signed by a CA that will soon
be blacklisted.

TODO: option to write/read the data to a db instead of to disk.
TODO: text/plain report, not just HTML.

Requirements:

* Python 3.x, including the OpenSSL module
* openssl 1.0.1 or greater
* permission to write to a subfolder
* Optional: webserver that does CGI


Install:

* dump these files into a folder
* run fetch\_ssl\_certs.py from a cronjob.  Hourly is fine.
* softlink check\_ssl\_certs.py to index.cgi

