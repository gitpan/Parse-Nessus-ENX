
package Parse::Nessus::ENX;

use strict;
use vars qw/ $VERSION @ISA @EXPORT_OK /;

require Exporter;

@ISA = qw/ Exporter /;
@EXPORT_OK = qw/ ebanners eports eplugin ewebdirs enfs eos esnmp/;

$VERSION = '.01';

use constant WEBDIR => 11032; # nessus plugin id for web directories discovered
use constant NFS => 10437; 	# nessus plugin id for nfs shares discovered
use constant NMAP1 => 10336;  # nessus plugin id for Nmap OS guess
use constant NMAP2 => 11268;  # nessus plugin id for Nmap OS guess
use constant QUESO => 10337;  # nessus plugin id for QueSO OS guess

sub ebanners {
  my (@ndata) = @_;
  my (@banners);
  foreach my $nbanner (@ndata) {
  if ($nbanner =~ /emote(.*)server (banner|type)/)  {
  my @result = split (/\|/, $nbanner);
	$result[4] =~ s/^(.*?) \:\;|Solution (.*)$|r\;|\;|This is(.*)$//g;
	push @banners , join "|" , $result[0] , $result[4];
  }

}
	return @banners;
}

sub eports {
my (@ndata) = @_;
my (@ports);
my $nport = pop(@ndata);
foreach my $ndata (@ndata) {
my @result = split (/\|/, $ndata);
if ($result[3] || $ndata =~ /\[NessusWX|\$DATA/) {
next;
}
elsif ($result[1] =~ /\($nport\//) {
push @ports , join "|" , $result[0] , $result[1];
}
}
return @ports;
}

sub eplugin {
my (@ndata) = @_;
my (@plugins);
my $eplugin = pop(@ndata);
foreach my $ndata (@ndata) {
my @result = split (/\|/, $ndata);
if (! $result[4]) {
next;
}
elsif ($result[2] =~ /$eplugin/) {
push @plugins, join "|" , $result[0] , $result[1] , $result[4];
}
}
return @plugins;
}

sub ewebdirs {
my (@ndata) = @_;
my (@webdirs);
my $webdirplugin = WEBDIR;
foreach my $ndata (@ndata) {
my @result = split (/\|/, $ndata);
if (! $result[4]) {
next;
}
elsif ($result[2] =~ /$webdirplugin/) {
$result[4] =~ s/(^(.*)discovered\:\;|\;|\,)//g;
$result[4] =~ s/The following(.*)authentication:/\|/;
push @webdirs, join "|" , $result[0] , $result[1] , $result[4];
}
}
return @webdirs;
}

sub enfs {
my (@ndata) = @_;
my (@nfs);
my $nfsplugin = NFS;
foreach my $ndata (@ndata) {
my @result = split (/\|/, $ndata);
if (! $result[4]) {
next;
}
elsif ($result[2] =~ /$nfsplugin/) {
$result[4] =~ s/(^(.*?) \: \;|\;\;CVE(.*)$)//g;
$result[4] =~ s/\;/,/g;
push @nfs, join "|" , $result[0] , $result[1] , $result[4];
}
}
return @nfs;
}

sub eos {
my (@ndata) = @_;
my (@os);
foreach my $ndata (@ndata) {
if ($ndata =~ m/10336\|(INFO|NOTE)|11268\|(INFO|NOTE)|10337\|(INFO|NOTE)/) {
my @result = split (/\|/, $ndata);
	if ($result[2] eq NMAP1) {
	$result[4] =~ s/(Nmap(.*)running |\;)//g;
	push @os , join "|" ,  $result[0] , $result[4];
	}
	elsif ($result[2] eq NMAP2) {
	$result[4] =~ s/(Remote OS guess : |\;\;(.*)$)//g;
	push @os , join "|" ,  $result[0] , $result[4];
	}
	elsif ($result[2] eq QUESO) {
	$result[4] =~ s/(QueSO has(.*) \;\* |\;\;\;CVE (.*)$| \(by (.*)$)//g;
	push @os , join "|" ,  $result[0] , $result[4];
	}
}
}
return @os;
}

sub esnmp {
my (@ndata) = @_;
my (@snmp);
foreach my $ndata (@ndata) {
if ($ndata =~ m/10264\|REPORT\|/) {
my @result = split (/\|/, $ndata);
        $result[4] =~ s/\;SNMP Agent(.*?)community name: //;
        $result[4] =~ s/(\;SNMP Agent (.*?)community name: |\;CVE(.*)$)/ /g;
        push @snmp, join "|" , $result[0] , $result[4];
        }
}
return @snmp;
}

1;

__END__

=pod

=head1 NAME

Parse::Nessus::ENX - extract specific data from nessusWX export files

=head1 SYNOPSIS

	use Parse::Nessus::ENX;

	function(@nessusdata);
	
	function(@nessusdata,$query);	

=head1 DESCRIPTION

This module is designed to extract information from nessusWX export files. 
Certain functions have been designed to return certain sets of data, 
such as service banners and OS versions. Other functions have been 
provided that will return more specific information, such as all IPs 
listening on a given port or all IPs associated with a specified plugin id.

=head1 EXAMPLES

To obtain a list of banners

	my @banners =  ebanners(@nessusdata);
	print @banners;
	
	# returns 
	IP|service banner
	...

To query by port

	my $port = 80;
	my @ports = eports(@nessusdata,$port);		
	print @ports;
	
	# returns 
	IP|specified port
	...

To obtain a list of web directories

	my @webdirs = ewebdirs(@nessusdata);		
	print @webdirs;
	
	# returns 
	IP|web port|web dir(s)|web dir(s) requiring authentication
	...

To obtain a list of nfs shares

	my @nfs = enfs(@nessusdata);				
	print @nfs;
	
	# returns 
	IP|nfs port|nfs share(s)
	...

To obtain a OS listing

	my @os = eos(@nessusdata);				
	print @os;
	
	# returns 
	IP|OS version
	...

To obtain a listing of SNMP community strings

	my @snmp = esnmp(@nessusdata);				
	print @snmp;

	# returns 
	IP|SNMP community string(s)
	...

To query by plugin id

	my $plugin = 10667;
	my @plugin = eplugin(@nessusdata,$plugin); 	
	print @plugin;

	# returns
	IP|port|plugin data
	...

=head1 AUTHOR

David J Kyger, dave@norootsquash.net

=head1 COPYRIGHT

Copyright 2003 David J Kyger. All rights reserved.

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut

