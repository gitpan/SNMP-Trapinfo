package SNMP::Trapinfo;

use 5.008004;
use strict;
use warnings;
use Carp;

our $VERSION = '0.8.1';

sub AUTOLOAD {
        my $self = shift;
        my $attr = our $AUTOLOAD;
        $attr =~ s/.*:://;
        return if $attr =~ /^DESTROY$/;
        if (@_) {
                return $self->{$attr} = shift;
        } else {
                return $self->{$attr};
        }
}

sub new {
	my ($class, $data) = @_;
	croak "Must specify data source (either GLOB or scalar ref)" unless $data;
	my $self = { 
			data => {}
			};
	$self = bless $self, $class;

	$self->read($data);
	return $self;
}

sub trapname {
	my $self = shift;
	my $trapname = $self->data->{"SNMPv2-MIB::snmpTrapOID"};
	return $trapname;
}

sub expand {
	my $self = shift;
	my $string = shift;
	my $key;
	while ( ($key) = ($string =~ /\${([\w\-:]+)}/) ) {
		my $newval;
		my ($action, $line) = $key =~ /^([PV])(\d+)?$/;
		if ($action && $line) {
			$newval = $self->$action($line);
		} elsif ($key eq "DUMP") {
			my %h = %{$self->data};
			delete $h{"SNMP-COMMUNITY-MIB::snmpTrapCommunity"};
			$newval = join(" ", map {"$_=".$self->data->{$_}} (sort keys %h) );
		} elsif ($key eq "TRAPNAME") {
			$newval = $self->trapname;
		} elsif ($key eq "HOSTIP") {
			$newval = $self->hostip;
		} else {
			$newval = $self->data->{$key} || "(null)";
		}
		$string =~ s/(\${[\w\-:]+})/$newval/;
	}
	return $string;
}

sub cleanup_string {
	my $self = shift;
	my $string = shift;
	# This is an SNMP OID name...
	if ($string =~ /^[A-Za-z].*\:\:[A-Za-z].*$/) {
		# Drop single trailing digits
		if (! ($string =~ /\d\.\d+$/)) {
			$string =~ s/\.\d+$//;
		}
	}
	return $string;
}

sub read {
	my ($self, $data) = @_;
	if (ref \$data eq "GLOB") {
		local $/=""; 
		$self->{packet} = <$data>;
	} elsif (ref \$data eq "REF") {
		$self->{packet} = $$data;
	} else {
		croak "Bad ref";
	}
	my @packet = split("\n", $self->{packet});
	chomp($_ = shift @packet);
	$self->hostname($_);
	chomp($_ = shift @packet);

	# Extra stuff around the IP packet in Net-SNMP 5.2.1
	s/^.*\[//;
	s/\].*$//;

	$self->hostip($_);
	foreach $_ (@packet) {
		my ($key, $value) = /^([^ ]+) (.+)$/;
		next unless $value;
		$key = $self->cleanup_string($key);
		if ($key ne "SNMPv2-MIB::snmpTrapOID") {
			$value = $self->cleanup_string($value);
		}
		$self->data->{"$key"} = $value;
	}
}

sub fully_translated {
	my $self = shift;
	if ($self->trapname =~ /\.\d+$/) {
		return 0;
	} else {
		return 1;
	}
}

sub _get_line {
	my ($self, $line) = @_;
	$line--;	# Index begins with 1
	my @packet = split("\n", $self->{packet});
	$_ = $packet[$line];
	# Return complete line if requesting P1 or P2
	if ($line == 0 or $line == 1) {
		return ($_, undef);
	}
	my ($key, undef, $value) = /^([^ ]+)( (.+))?$/;
	$key = $self->cleanup_string($key);
	$value = $self->cleanup_string($value) if $value;
	return ($key, $value);
}
		
sub P {
	my ($self, $line) = @_;
	my ($key, $value) = $self->_get_line($line);
	$key =~ s/^[^:]+:://;
	return $key;
}

sub V {
	my ($self, $line) = @_;
	my ($key, $value) = $self->_get_line($line);
	return $value;
}

1;
__END__

=head1 NAME

SNMP::Trapinfo - Reading an SNMP trap from Net-SNMP's snmptrapd

=head1 SYNOPSIS

  use SNMP::Trapinfo;
  $trap = SNMP::Trapinfo->new(*STDIN);

  print "From host: ", $trap->hostname, $/;
  print "Trapname: ", $trap->trapname, $/;
  print "Packet: ", $trap->packet, $/;
  print "Message: ", $trap->expand('Interface ${V5} is down'), $/;

=head1 DESCRIPTION

This module allows the user to get to the useful parts of an snmptrapd
packet. This assumes that you are using the Net-SNMP package from
http://www.net-snmp.org and that you are letting snmptrapd do all the
OID translations (no -On option for snmptrapd) and that hostnames are resolved
itself (no -n option).

The most useful method is expand, which evaluates macros based on the packet,
for your custom messages.

=head1 METHODS

=over 4

=item SNMP::Trapinfo->new(*STDIN)

Reads STDIN, expecting input from snmptrapd, and returns the object holding all the information 
about this packet. An example packet is:

  cisco2611.lon.altinity
  192.168.10.20
  SNMPv2-MIB::sysUpTime.0 9:16:47:53.80
  SNMPv2-MIB::snmpTrapOID.0 IF-MIB::linkUp.1
  IF-MIB::ifIndex.2 2
  IF-MIB::ifDescr.2 Serial0/0
  IF-MIB::ifType.2 ppp
  SNMPv2-SMI::enterprises.9.2.2.1.1.20.2 "PPP LCP Open"
  SNMP-COMMUNITY-MIB::snmpTrapAddress.0 192.168.10.20
  SNMP-COMMUNITY-MIB::snmpTrapCommunity.0 "public"
  SNMPv2-MIB::snmpTrapEnterprise.0 SNMPv2-SMI::enterprises.9.1.186

=item SNMP::Trapinfo->new(\$data)

Instead of a filehandle, can specify a scalar reference that holds the packet data.

=item hostname

Returns the first line of the packet, which should be the hostname as
resolved by snmptrapd.

=item hostip

Returns the IP address in the 2nd line of the packet, which should be the 
originating host.

=item trapname

Returns the value of the parameter SNMPv2-MIB::snmpTrapOID. In the
example above, this method would return IF-MIB::linkUp. The .1 is removed,
but if it was .1.1, this would not be removed.

=item fully_translated

Returns 0 if the trapname has more than 1 set of trailing digits
(a single .\d+ would be removed automatically) - this would mean that a
MIB is missing. Otherwise returns 1.

=item data

Returns a hash ref where the keys consist of the SNMP parameter and
the values are the string values of thos parameters. For the example 
trap above, a Data::Dumper of $trap->data would give:

  $VAR1 = {
          'SNMPv2-MIB::snmpTrapEnterprise' => 'SNMPv2-SMI::enterprises.9.1.186',
          'SNMP-COMMUNITY-MIB::snmpTrapAddress' => '192.168.10.20',
          'IF-MIB::ifType' => 'ppp',
          'IF-MIB::ifIndex' => '2',
          'SNMPv2-MIB::snmpTrapOID' => 'IF-MIB::linkUp.1',
          'IF-MIB::ifDescr' => 'Serial0/0',
          'SNMP-COMMUNITY-MIB::snmpTrapCommunity' => '"public"',
          'SNMPv2-MIB::sysUpTime' => '9:16:47:53.80',
          'SNMPv2-SMI::enterprises.9.2.2.1.1.20.2' => '"PPP LCP Open"'
        };

=item expand($string)

Takes $string and expands it so that macros within the string will be expanded
out based on the packet details. Available macros are:

=over 4

=item *

${Px} - Returns the parameter for line x

=item *

${Vx} - Returns the value for line x

=item *

${TRAPNAME} - Returns the trapname (as called from $trap->trapname)

=item *

${HOSTIP} - Returns the IP of the originating packet

=item *

${IF-MIB::ifType} - Returns the value for the specified parameter. 

=item *

${DUMP} - Returns all key, value pairs (stripping out snmpTrapCommunity)

=back

For the example trap above, if you ran:

  $trap->expand('Port ${IF-MIB::ifIndex} (${P7}=${V7}) is Up with message ${V8}'); 

this would return:

  Port 2 (ifType=ppp) is Up with message "PPP LCP Open"

=back

=head1 SEE ALSO

Net-SNMP - http://www.net-snmp.org

=head1 AUTHOR

Ton Voon, E<lt>ton.voon@altinity.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Altinity Limited

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
