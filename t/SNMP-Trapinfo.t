# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl SNMP-Trapinfo.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 30;
BEGIN { use_ok('SNMP::Trapinfo') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

use strict;
use warnings;
use File::Temp qw(tempfile);

my $fh = tempfile();

print $fh <<EOF;
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

cisco2620.lon.altinity
192.168.10.30
SNMPv2-MIB::sysUpTime.0 9:16:47:53.80
SNMPv2-MIB::snmpTrapOID.0 IF-MIB::linkUp.1
IF-MIB::ifIndex.2 12
IF-MIB::ifDescr.2 Serial0/0
IF-MIB::ifType.2 ppp
EOF
seek ($fh, 0, 0);

my $trap = SNMP::Trapinfo->new(*$fh);
isa_ok( $trap, "SNMP::Trapinfo");

cmp_ok( $trap->hostname, 'eq', "cisco2611.lon.altinity", "Host name parsed correctly");
cmp_ok( $trap->hostip, 'eq', "192.168.10.20", "Host ip parsed correctly");
cmp_ok( $trap->trapname, 'eq', "IF-MIB::linkUp.1", "trapname correct");
cmp_ok( $trap->fully_translated, '==', 0, "trapname is not fully translated");
cmp_ok( $trap->data->{"SNMPv2-SMI::enterprises.9.2.2.1.1.20.2"}, 'eq', '"PPP LCP Open"', "Parse spaces correctly");
cmp_ok( $trap->P(3), 'eq', "sysUpTime", "Got p3 correctly");
cmp_ok( $trap->P(9), 'eq', "snmpTrapAddress", "Got p9 correctly");
cmp_ok( $trap->V(5), '==', 2, "Got v5 correctly");
cmp_ok( $trap->V(8), 'eq', '"PPP LCP Open"', "Got v8 correctly");
cmp_ok( $trap->expand('Port ${IF-MIB::ifIndex} (${P7}=${V7}) is Up with message ${V8}'), 'eq', 
	'Port 2 (ifType=ppp) is Up with message "PPP LCP Open"', "Macro expansion as expected");

my $expected = 'cisco2611.lon.altinity
192.168.10.20
SNMPv2-MIB::sysUpTime.0 9:16:47:53.80
SNMPv2-MIB::snmpTrapOID.0 IF-MIB::linkUp.1
IF-MIB::ifIndex.2 2
IF-MIB::ifDescr.2 Serial0/0
IF-MIB::ifType.2 ppp
SNMPv2-SMI::enterprises.9.2.2.1.1.20.2 "PPP LCP Open"
SNMP-COMMUNITY-MIB::snmpTrapAddress.0 192.168.10.20
SNMP-COMMUNITY-MIB::snmpTrapCommunity.0 "*****"
SNMPv2-MIB::snmpTrapEnterprise.0 SNMPv2-SMI::enterprises.9.1.186';
cmp_ok( $trap->packet( {hide_passwords=>1} ), 'eq', $expected, "Got full packet with passwords hidden");

$trap = SNMP::Trapinfo->new(*$fh);
cmp_ok( $trap->hostname, 'eq', "cisco2620.lon.altinity", "Host name parsed correctly for subsequent packet");
$expected = 'cisco2620.lon.altinity
192.168.10.30
SNMPv2-MIB::sysUpTime.0 9:16:47:53.80
SNMPv2-MIB::snmpTrapOID.0 IF-MIB::linkUp.1
IF-MIB::ifIndex.2 12
IF-MIB::ifDescr.2 Serial0/0
IF-MIB::ifType.2 ppp';
cmp_ok( $trap->packet, 'eq', $expected, "Got full packet without passwords hidden");

ok( ! defined SNMP::Trapinfo->new(*$fh), "No more packets");

eval '$trap = SNMP::Trapinfo->new';
cmp_ok( $@, 'ne',"", "Complain if no parameters specified for new()");

my $data = <<EOF;
cisco9999.lon.altinity
UDP: [192.168.10.21]:3656
SNMPv2-MIB::sysUpTime.0 75:22:57:17.87
SNMPv2-MIB::snmpTrapOID.0 IF-MIB::linkDown
IF-MIB::ifIndex.24 24
IF-MIB::ifDescr.24 FastEthernet0/24
IF-MIB::ifType.24 ethernetCsmacd
SNMP-COMMUNITY-MIB::snmpTrapAddress.0 192.168.10.21
SNMP-COMMUNITY-MIB::snmpTrapCommunity.0 "public"
EOF

eval '$trap = SNMP::Trapinfo->new($data)';
like( $@, '/Bad ref/', "Complain if bad parameters for new()");

$trap = SNMP::Trapinfo->new(\$data);
cmp_ok( $trap->hostip, 'eq', "192.168.10.21", "Host ip correct");
cmp_ok( $trap->trapname, 'eq', "IF-MIB::linkDown", "trapname correct");
cmp_ok( $trap->expand('This IP is ${HOSTIP}'), 'eq', 'This IP is 192.168.10.21', '${HOSTIP} expands correctly');
cmp_ok( $trap->fully_translated, '==', 1, "Trapname is fully translated");
cmp_ok( $trap->data->{"IF-MIB::ifDescr"}, "eq", "FastEthernet0/24", "Got interface description");

$_ = $trap->expand('Port ${IF-MIB::ifIndex} (type ${IF-MIB::ifType}, description "${IF-MIB::ifDescr}") is down or ${rubbish}');
cmp_ok( $_, "eq", 'Port 24 (type ethernetCsmacd, description "FastEthernet0/24") is down or (null)',
	"Can evaluate message");

$_ = $trap->expand('Received ${TRAPNAME}: ${DUMP}');
cmp_ok( $_, "eq", 'Received IF-MIB::linkDown: IF-MIB::ifDescr=FastEthernet0/24 IF-MIB::ifIndex=24 IF-MIB::ifType=ethernetCsmacd SNMP-COMMUNITY-MIB::snmpTrapAddress=192.168.10.21 SNMPv2-MIB::snmpTrapOID=IF-MIB::linkDown SNMPv2-MIB::sysUpTime=75:22:57:17.87', "Dump correct");

cmp_ok($trap->expand('Interface ${V5} is down'), "eq", 'Interface 24 is down', 'Expansion of ${V5} correct');
cmp_ok($trap->expand('Extra data: ${P7} = ${V7}'), "eq", 'Extra data: ifType = ethernetCsmacd', 'Expansion of ${P7} and ${V7} correct');
cmp_ok($trap->expand('IP: ${P2}'), 'eq', 'IP: UDP: [192.168.10.21]:3656', '${P2} works');
cmp_ok($trap->expand('Bad - ${P}'), 'eq', 'Bad - (null)', '${P} without a number caught correctly');

$data = <<EOF;
192.168.144.197
UDP: [192.168.144.197]:40931
SNMPv2-SMI::mib-2.1.3.0 0:1:49:29.00
SNMPv2-SMI::snmpModules.1.1.4.1.0 ISHELF-ARCS-MIB::iShelfTrapGroup.5.0
ISHELF-SYS-MIB::iShelfSysTrapDbChgOid.0 ISHELF-CARD-MIB::iShelfCardLocation.10112
ISHELF-SYS-MIB::iShelfSysSystemDateTime.0 Wrong Type (should be OCTET STRING): 27
EOF

$trap = SNMP::Trapinfo->new(\$data);
ok( ! defined $trap->trapname, "Trapname not in packet");
