This is a demo project that builds a CloudFront middleware plugin for Munki 7.

It is a port of Aaron Burchfield's CloudFront-Middleware:
https://github.com/AaronBurchfield/CloudFront-Middleware

The middleware plugin must be installed in /usr/local/munki/middleware/, and you need Munki 7.0.0.5139 or later to test.

To build the middleware plugin and an Installer pkg that installs it, cd into this directory and run `./build_pkg.sh`. You will need a recent version of Xcode.
