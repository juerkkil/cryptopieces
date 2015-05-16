#!/usr/bin/perl 

# Simple script to make HTTPS request and verify certificates.
# Also verifies that the hostname in cert matches to hostname of server.
# Written for Aalto University course T-110.5241
# Jussi-Pekka Erkkilä <juerkkil@iki.fi>, 2012

# requres libwww-perl and openssl

use LWP::UserAgent 6;

# Set up necessary environment variables to verify certificates and hostnames 
$ENV{HTTPS_VERSION} = 3;
$ENV{HTTPS_CA_DIR}  = '/etc/ssl/certs';
$ENV{HTTPS_CA_FILE} = '/etc/ssl/certs/ca-certificates.crt';
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 1;
 
# Read cmd args
$host = $ARGV[0];
$port = $ARGV[1];

# Make sure that args given
if(!defined $host || !defined $port) {
  print "Usage: perl ssl.pl [host] [port]\n";
  return 1;
}

# set up SSL destination
my $url = 'https://'.$host.':'.$port;
my $ua = new LWP::UserAgent;

$ua->timeout(10); # timeout in 10 secs
 
# create http get reqest
my $request = HTTP::Request->new('GET');
$request->url($url);
 
# fire 
my $response = $ua->request($request);

# print content, in case of error print error message
if($response->is_success) {
  print $response->decoded_content;
} else {
  print $response->status_line;
  die;
}
