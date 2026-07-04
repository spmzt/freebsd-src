import unittest
import asyncio


class TestParserMethods(unittest.TestCase):
    fw_loader = ["./ipfw-loader ", "-q", "-t", "-6"]

    async def exec(self, rules: str) -> [int, bytes]:
        process = await asyncio.create_subprocess_shell(
            " ".join(self.fw_loader),
            stdin=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate(rules.encode())
        return process.returncode, stderr

    def parse_rules(self, rules: str) -> [int, str]:
        result, msg = asyncio.run(self.exec(rules))
        return result, rules + msg.decode()

    def EXPECT_TRUE(self, rules: str):
        result, msg = self.parse_rules(rules)
        self.assertEqual(result, 0, msg)

    def EXPECT_FALSE(self, rules: str):
        result, msg = self.parse_rules(rules)
        self.assertNotEqual(result, 0, msg)


# -------------------- YaNET controlplane/parser tests ----------------------
class TestYanetParser(TestParserMethods):
    def test_001_Basic(self):
        rules = """
add allow tcp from any to any 22
"""
        self.EXPECT_TRUE(rules)

    def test_002_Sequence(self):
        rules = """
add allow tcp from any to any 80,443
"""
        self.EXPECT_TRUE(rules)

    def test_003_Range(self):
        rules = """
add allow tcp from any to any 5000-65535
"""
        self.EXPECT_TRUE(rules)

    def test_004_Multiline(self):
        rules = """
add allow tcp from any to any 22
add allow tcp from any to any 80,443
add allow tcp from any to any 1000-1024
"""
        self.EXPECT_TRUE(rules)

    def test_005_MultipleProtocols(self):
        rules = """
add allow { tcp or udp } from any to any 5000-65535
"""
        self.EXPECT_TRUE(rules)

    def test_006_MultipleTargets(self):
        rules = """
add allow tcp from 127.0.0.1 to { 192.168.0.1 or 172.0.0.1/24 } 80
"""
        self.EXPECT_TRUE(rules)

    def test_007_MultipleTargetsWithoutSpaces(self):
        rules = """
add allow tcp from 127.0.0.1 to {192.168.0.1 or 172.0.0.1/24} 80
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support macro definitions")
    def test_008_Macro(self):
        rules = """
# Macros cache entries:
_CLOUDINFRANETS_: 2a0d:d6c0::/32, 2a0d:d6c0:400::/48, 2a02:6b8:c00::59db:0:0/ffff:ffff:ff00:0:ffff:ffff::
_CLIENTSNETS_: 77.75.152.0/21, 109.235.160.0/21, 185.71.76.0/22, 2a02:5180::/32, 199.7.82.0/23, 2001:500:3::/48, 2001:500:9f::/48

add allow tcp from 127.0.0.1 to { _CLOUDINFRANETS_ } 80
add allow tcp from {_CLIENTSNETS_} to { _CLOUDINFRANETS_ } 80,443
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support DNS cache entry definitions")
    def test_009_Hostname(self):
        rules = """
# DNS Cache entry
sas-packfw01.tst.net.yandex.net 5.255.219.145,2a02:6b8:c02:5e1:0:675:62c5:442c actual noc-cc

add allow tcp from 127.0.0.1 to { sas-packfw01.tst.net.yandex.net } 80
"""
        self.EXPECT_TRUE(rules)

    def test_010_OutOption(self):
        rules = """
add allow tcp from any to any 80 out
"""
        self.EXPECT_TRUE(rules)

    def test_011_ViaOption(self):
        rules = """
add allow tcp from any to any 80 out via vlan659
"""
        self.EXPECT_TRUE(rules)

    def test_012_IcmpTypesOption(self):
        rules = """
add allow ip from any to any icmptype 11
add allow icmp from any to any icmptypes 0,8,3,11,12
add allow ip from any to any icmp6types 1,2,3,4,128,129,133,134,135,136
"""
        self.EXPECT_TRUE(rules)

    def test_013_FragOption(self):
        rules = """
add allow ip from any to any frag
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support macro definitions")
    def test_014_SrcPortOption(self):
        rules = """
_ROUTERSNETS_: 5.45.193.128/29, 2a02:6b8:0:6::/64
_VRFCONNECT_: 87.250.225.0/29, 95.108.136.200/29
add allow tcp from me to { _ROUTERSNETS_ or _VRFCONNECT_ } src-port 179
add allow tcp from any 179 to me
add allow udp from any src-port 53 to any
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support macro definitions")
    def test_015_DstPortOption(self):
        rules = """
_ROUTERSNETS_: 5.45.193.128/29, 2a02:6b8:0:6::/64
_VRFCONNECT_: 87.250.225.0/29, 95.108.136.200/29

add allow udp from { _ROUTERSNETS_ or _VRFCONNECT_ } to { _ROUTERSNETS_ or _VRFCONNECT_ } dst-port 3784,4784
add allow tcp from any to any 80,443
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support macro definitions")
    def test_016_DstPortOption(self):
        rules = """
_ROUTERSNETS_: 5.45.193.128/29, 2a02:6b8:0:6::/64
_VRFCONNECT_: 87.250.225.0/29, 95.108.136.200/29

# dst-port option is not allowed after src-statement
add allow udp from { _ROUTERSNETS_ or _VRFCONNECT_ } dst-port 3784,4784 to { _ROUTERSNETS_ or _VRFCONNECT_ }
"""
        self.EXPECT_FALSE(rules)

    def test_017_KeepStateOption(self):
        rules = """
add allow icmp from me to any icmptypes 8 out keep-state
"""
        self.EXPECT_TRUE(rules)

    def test_018_TcpFlagsOption(self):
        rules = """
add allow tcp from { 37.9.88.160/28 or 37.140.141.96/28 } to { 199.36.240.0/22 or 213.180.192.0/19  } established
add skipto :HBF_SKIP_CHECKSTATE tcp from any to any tcpflags syn,!ack
add deny tcp from any to any setup
add deny tcp from any to any tcpflags !syn,!fin,!ack,!psh,!rst,!urg
add deny tcp from any to any tcpflags fin,psh,urg
:HBF_SKIP_CHECKSTATE
add allow tcp from any to any tcpflags rst
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support macro definitions")
    def test_019_ProtoOption(self):
        rules = """
# DNS cache
man1-rt1.yndx.net 2a02:6b8:b011:6407:e61d:2dff:fe01:fa20 actual agodin,azatkurbanov
noc-sas.yandex.net 93.158.158.93,2a02:6b8:b010:31::100 actual gescheit,lytboris
noc-sas-jump.yandex.net 93.158.158.91,2a02:6b8:b010:31::ffff actual

# Macros
_YANDEXNETS_: 5.45.192.0/18, 2a02:6b8::/32
_TUN64_ANYCAST_: 2a02:6b8:b010:a0ff::/64, 2a02:6b8:b010:a0fd::/64, 2a02:6b8:b010:a0fc::/64
_NOCMGMTSRV_: man1-rt1.yndx.net, noc-sas.yandex.net, noc-sas-jump.yandex.net
_YANDEXNETS6_: 2620:10f:d000::/44, 2a02:6b8::/32, 2a0e:fd80::/32
_IPIP_SOURCES_: 5.45.193.128/29, 2a02:6b8:b010:a0fe::/64, 2a02:6b8:6666::/64

add allow ip from { _YANDEXNETS_ } to { _TUN64_ANYCAST_ } proto ipencap in
add allow tag 653 ip4 from { 172.20.0.0/16 } to { _NOCMGMTSRV_ } { proto tcp or proto icmp or proto udp }
add allow ip from { _IPIP_SOURCES_ } to { _YANDEXNETS6_ } proto ipv6 out
"""
        self.EXPECT_TRUE(rules)

    def test_020_IgnoredOptions(self):
        rules = """
# just ignore antispoof, diverted, logamount, tag, tagged,
# check-state
add allow tcp from 10.0.0.0/8 to 10.0.0.0/8 80 in antispoof
add 65534 allow ip from any to any diverted keep-state
add deny log logamount 500 all from any to any
add allow tag 653 ip4 from { 10.0.0.0/8 } to me
add check-state
add allow ip from any to any tagged 31000
add skipto :DSCP_ROUTING_TAIL ip from any to any not tagged 63
add allow tcp from any to any 5000-65535
:DSCP_ROUTING_TAIL
add count ip from any to any
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support macro definitions")
    def test_021_NamedPorts(self):
        rules = """
_YANDEXNETS_: 5.45.192.0/18, 2a02:6b8::/32
add allow udp from { _YANDEXNETS_ } bootpc,bootps to me bootps
"""
        self.EXPECT_TRUE(rules)

    def test_022_OctalIPv4(self):
        rules = """
# inet_pton() fails to parse octets in octal form
# but inet_aton() does it.
add allow tcp from 192.168.001.010 to any 80
"""
        self.EXPECT_TRUE(rules)

    def test_023_IPv6(self):
        rules = """
add allow tcp from ::/:: to any 80
add allow tcp from ::1 to any 80
add allow tcp from ::2:1 to any 80
add allow tcp from ::3:2:1 to any 80
add allow tcp from ::4:3:2:1 to any 80
add allow tcp from ::5:4:3:2:1 to any 80
add allow tcp from ::6:5:4:3:2:1 to any 80
add allow tcp from ::7:6:5:4:3:2:1 to any 80
add allow tcp from 8:7:6:5:4:3:2:1 to ::ffff:0.0.0.1 80
add allow udp from ::ffff/96 to any 53
add allow udp from me to { 2a02:6b8:0:10::77.88.6.64 } out
"""
        self.EXPECT_TRUE(rules)

    def test_024_Tables(self):
        rules = """
# Implicit automatic table creation
table _ROUTERLOOPBACKS_ add 5.45.193.144/29
table _ROUTERLOOPBACKS_ add 5.45.200.24/30
table _ROUTERLOOPBACKS_ add 5.45.203.64/31

# Explicit table creation
table _NAT64_LAST_HOP_ENABLED_IFACES_ create type iface
table _NAT64_LAST_HOP_ENABLED_IFACES_ add vlan2612 :IPMINETS_OUT_ALLOW
table _NAT64_LAST_HOP_ENABLED_IFACES_ add vlan475 :MARKETWHINDUSTRIALDEVICENETS_OUT_ALLOW

# Skipto via prefix tables
table _SKIPTO_SRC_PREFIX_ add 5.45.192.0/18 :TUN64_TOWORLD_FASTTCP
table _SKIPTO_SRC_PREFIX_ add 80.239.142.160/27 :TUN64_TOWORLD_TURBO
table _SKIPTO_SRC_PREFIX_ add 77.88.46.0/25 :TUN64_TOWORLD_MEDIASTORAGE

# Expand tables
add allow icmp from { table(_ROUTERLOOPBACKS_) } to any
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support macro definitions")
    def test_026_AllowFromYandexNets(self):
        rules = """
_YANDEXNETS_: 5.45.192.0/18, 2a02:6b8::/32
_EXTFACTORIESNETS_: 95.108.146.0/27, 95.108.146.128/27, 2a02:6b8:0:d100::/56
ALLOW_FROM_YANDEXNETS(tcp, { 2a02:6b8:0:3400::146 or 5.255.240.146 }, 80,443)
ALLOW_FROM_YANDEXNETS({ tcp or udp }, { _EXTFACTORIESNETS_ }, )
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support DNS cache entry definitions")
    def test_027_AllowFromAny(self):
        rules = """
botanik-dev.yandex.net 5.255.214.33,2a02:6b8:c02:c04:0:690:909b:6b88 actual mzelenkov,inkvizitor68sl
cipt-m9-phone1.yndx.net 5.45.220.231,2a02:6b8:0:200f::8 actual ip-tel,noc-office
_TAXI_COTURN_NETS_: 2a02:6b8:c00::51d0:0:0/ffff:ffff:ff00:0:ffff:ffff::
ALLOW_FROM_ANY(udp, { _TAXI_COTURN_NETS_ }, 3478,3479,49152-65535)
ALLOW_FROM_ANY(udp, { cipt-m9-phone1.yndx.net }, 5081-65535,5000-5079)
ALLOW_FROM_ANY(esp, { botanik-dev.yandex.net }, )
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support macro definitions")
    def test_028_Comments(self):
        rules = """
# comments, empty commens, commented rules, rule's comments
#
# add allow ip from any to any src-port 53 dst-port 49152-65535
_DISK_TUN64_NETS_: 5.45.195.136/29, 37.9.68.192/26
add skipto :ME_SECTION ip from me to any // ME_SECTION
add allow ip from any to { _DISK_TUN64_NETS_ } // TUN64_TO_DISK
"""
        self.EXPECT_TRUE(rules)

    def test_029_SkiptoBackwards(self):
        rules = """
:BEGIN
add skipto :BEGIN ip from any to any
"""
        self.EXPECT_FALSE(rules)

    def test_030_SkiptoBackwards(self):
        rules = """
:BEGIN
add 100 skipto 50 ip from any to any
"""
        self.EXPECT_FALSE(rules)

    def test_031_LabelBetweenRules(self):
        rules = """
:BEGIN
add 100 allow ip from any to any
:HBF_IN
add 100 allow tcp from any to any
"""
        self.EXPECT_FALSE(rules)

    def test_032_UnknownMacro(self):
        rules = """
:BEGIN
add 100 allow ip from { _YANDEXNETS_ } to any
"""
        self.EXPECT_FALSE(rules)

    def test_033_UnknownHostname(self):
        rules = """
:BEGIN
add 100 allow ip from { sas-packfw01.tst.net.yandex.net } to any
"""
        self.EXPECT_FALSE(rules)

    @unittest.skip("do not support macro definitions")
    def test_034_UnknownHostnameInMacro(self):
        rules = """
# macro has unknown hostname
_TESTING_HOSTS_: sas-packfw01.tst.net.yandex.net
:BEGIN
add 100 allow ip from { _TESTING_HOSTS_ } to any
"""
        self.EXPECT_FALSE(rules)

    @unittest.skip("do not support macro definitions")
    def test_035_UnknownHostnameInMacro(self):
        rules = """
# macro has unknown hostname, but it also has IPv4 network
_TESTING_HOSTS_: sas-packfw01.tst.net.yandex.net, 109.235.160.0/21
:BEGIN
add 100 allow ip from { _TESTING_HOSTS_ } to any
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support macro definitions")
    def test_036_UnknownHostnameInMacro(self):
        rules = """
# empty macro, but target source in rules still valid
_TESTING_HOSTS_: sas-packfw01.tst.net.yandex.net
:BEGIN
add 100 allow ip from { _TESTING_HOSTS_ or 109.235.160.0/21 } to any
add 200 allow tcp from { sas-packfw02.tst.net.yandex.net or 109.235.160.0/21 } to any
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support compact form")
    def test_037_CompactFormat(self):
        rules = """
:BEGIN
add 100 allow proto tcp src-addr 109.235.160.0/21 in via vlan802
add 150 allow icmptypes 0,8
add 200 allow icmp6types 135,136
add 250 allow proto udp dst-port 53
add 300 deny
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support compact form")
    def test_038_CompactFormatUnknownMacro(self):
        rules = """
:BEGIN
add 100 allow proto tcp src-addr _TESTING_HOSTS_ in via vlan802
"""
        self.EXPECT_FALSE(rules)

    @unittest.skip("do not support compact form")
    def test_039_CompactFormatUnknownHostname(self):
        rules = """
:BEGIN
add 100 allow proto tcp src-addr sas-packfw01.tst.net.yandex.net in via vlan802
"""
        self.EXPECT_FALSE(rules)

    @unittest.skip("do not support macro definitions")
    def test_040_M4EscapedHostname(self):
        rules = """
# DNS Cache entries
audit-win10-1-v32.ld.yandex-team.ru 2a02:6b8:c0e:108:0:430c:f32:101 actual aquila,gots,mitt
index.splunk.yandex.net 95.108.236.1,2a02:6b8:c03:77e:0:557:9092:85ac actual dmrussak,gots,limetime,sungurov

# Macros
_WINSOCSRV_: audit-win10-1-v32.ld.yandex-team.ru

:BEGIN
add allow tcp from { _WINSOCSRV_ } to { `index.splunk.yandex.net' } 3030,3333

# Compact form
add allow proto tcp dst-addr `index.splunk.yandex.net' dst-port 3030,3333
"""
        self.EXPECT_TRUE(rules)

    def test_041_UnknownLabel(self):
        rules = """
:BEGIN
add 100 skipto :HBF_IN ip from any to any
"""
        self.EXPECT_FALSE(rules)

    def test_042_SkiptoTablearg(self):
        rules = """
# Basic test for skipto tablearg via table(N)
table _SKIPTO_IN_ create type iface
table _SKIPTO_IN_ add vlan141 :INSTALLNETS
table _SKIPTO_IN_ add vlan1401 :RNDNETS
table _SKIPTO_IN_ add lp.kni0.1600 :VRF_Hbf

:BEGIN
add skipto tablearg ip from any to any via table(_SKIPTO_IN_) in
"""
        self.EXPECT_TRUE(rules)

    def test_043_SkiptoTablearg(self):
        rules = """
# table N has not been defined
:BEGIN
add skipto tablearg ip from any to any via table(_SKIPTO_IN_) in
"""
        self.EXPECT_FALSE(rules)

    def test_044_SkiptoTablearg(self):
        rules = """
# table N has wrong type
table _SKIPTO_IN_ add 10.0.0.1/24
:BEGIN
add skipto tablearg ip from any to any via table(_SKIPTO_IN_) in
"""
        self.EXPECT_FALSE(rules)

    def test_045_SkiptoTablearg(self):
        rules = """
# Basic test for skipto tablearg
table _SKIPTO_DST_PREFIX_ add 5.45.192.0/18 :TUN64_FROMWORLD_FASTTCP
table _SKIPTO_DST_PREFIX_ add 80.239.142.160/27 :TUN64_FROMWORLD_TURBO
table _SKIPTO_DST_PREFIX_ add 77.88.46.128/29 :TUN64_FROMWORLD_FASTTCP_DNS
table _SKIPTO_DST_PREFIX_ add 77.88.46.160/27 :TUN64_FROMWORLD_FASTTCP_DNS
table _SKIPTO_DST_PREFIX_ add 77.88.56.0/26 :TUN64_FROMWORLD_FASTTCP_DNS

:BEGIN
add skipto tablearg ip from any to table(_SKIPTO_DST_PREFIX_)
"""
        self.EXPECT_TRUE(rules)

    def test_046_SkiptoTablearg(self):
        rules = """
# table N has not been defined
:BEGIN
add skipto tablearg ip from any to table(_SKIPTO_DST_PREFIX_)
"""
        self.EXPECT_FALSE(rules)

    def test_047_SkiptoTablearg(self):
        rules = """
# table N has wrong type
table _SKIPTO_IN_ create type iface
table _SKIPTO_IN_ add vlan141 :INSTALLNETS
table _SKIPTO_IN_ add vlan1401 :RNDNETS
:BEGIN
add skipto tablearg ip from any to table(_SKIPTO_IN_)
"""
        self.EXPECT_FALSE(rules)

    def test_048_SkiptoTablearg(self):
        rules = """
# several tables specified for tablearg (not supported yet)
table _SKIPTO_DST_PREFIX_ add 80.239.142.160/27 :TUN64_FROMWORLD_TURBO
table _SKIPTO_SRC_PREFIX_ add 77.88.46.128/29 :TUN64_FROMWORLD_FASTTCP_DNS

:BEGIN
add skipto tablearg ip from table(_SKIPTO_SRC_PREFIX_) to table(_SKIPTO_DST_PREFIX_)
"""
        self.EXPECT_FALSE(rules)

    def test_049_ViaTable(self):
        rules = """
# Basic test for via table
table _PASS_THROUGH_IFACES_ create type iface
table _PASS_THROUGH_IFACES_ add vlan1610
table _PASS_THROUGH_IFACES_ add vlan829
table _PASS_THROUGH_IFACES_ add vlan827
table _PASS_THROUGH_IFACES_ add vlan1611

:BEGIN
add allow ip from any to any via table(_PASS_THROUGH_IFACES_)
"""
        self.EXPECT_TRUE(rules)

    def test_050_Prefixlen(self):
        rules = """
# various prefix len for IPv4/IPv6 prefixes
:BEGIN
add allow ip from any to 10.0.0.1/0
add allow ip from any to 10.0.0.1/28
add allow ip from any to 10.0.0.1/32
add allow ip from any to fe80::1/0
add allow ip from any to fe80::1/8
add allow ip from any to fe80::1/32
add allow ip from any to fe80::1/64
add allow ip from any to fe80::1/128
"""
        self.EXPECT_TRUE(rules)

    def test_051_Prefixlen(self):
        rules = """
# bad prefixlen
:BEGIN
add allow ip from any to 10.0.0.1/128
"""
        self.EXPECT_FALSE(rules)

    def test_052_Prefixlen(self):
        rules = """
# bad prefixlen
:BEGIN
add allow ip from any to fe80::1/100500
"""
        self.EXPECT_FALSE(rules)

    def test_053_SkiptoBackwards(self):
        rules = """
:BEGIN
add 100 skipto 100 ip from any to any
"""
        self.EXPECT_FALSE(rules)

    @unittest.skip("do not support compact form")
    def test_054_NumericProtoOption(self):
        rules = """
:BEGIN
add allow 17 from any to any
add allow proto 6
add allow ip from any to any proto 58
"""
        self.EXPECT_TRUE(rules)

    def test_055_SkiptoTablearg(self):
        rules = """
# One enty added without label. This is allowed, but it won't work,
# since unwind() will ignore this entry.
table _SKIPTO_DST_PREFIX_ create type addr
table _SKIPTO_DST_PREFIX_ add 5.45.192.0/18 :TUN64_FROMWORLD_FASTTCP
table _SKIPTO_DST_PREFIX_ add 80.239.142.160/27 :TUN64_FROMWORLD_TURBO
table _SKIPTO_DST_PREFIX_ add 77.88.56.0/26

:BEGIN
add skipto tablearg ip from any to table(_SKIPTO_DST_PREFIX_)
"""
        self.EXPECT_TRUE(rules)

    @unittest.skip("do not support DNS cache entry definitions")
    def test_055_TableWithHostnames(self):
        rules = """
# DNS Cache entry
sas-packfw01.tst.net.yandex.net 5.255.219.145,2a02:6b8:c02:5e1:0:675:62c5:442c actual noc-cc
noc-sas-jump.yandex.net 93.158.158.91,2a02:6b8:b010:31::ffff actual

table _SKIPTO_DST_PREFIX_ create type addr
table _SKIPTO_DST_PREFIX_ add sas-packfw01.tst.net.yandex.net :TUN64_FROMWORLD_FASTTCP
table _SKIPTO_DST_PREFIX_ add noc-sas-jump.yandex.net

:BEGIN
add skipto tablearg ip from any to table(_SKIPTO_DST_PREFIX_)
"""
        self.EXPECT_TRUE(rules)

    def test_056_UnknownHostnameInTable(self):
        rules = """
# unknown hostname in table leads to empty dst addresses
table _SKIPTO_DST_PREFIX_ create type addr
table _SKIPTO_DST_PREFIX_ add noc-sas-jump.yandex.net

:BEGIN
add allow ip from any to { table(_SKIPTO_DST_PREFIX_) }
"""
        self.EXPECT_FALSE(rules)

    def test_057_AnyOverridesEmptyDestination(self):
        rules = """
# unknown hostname in table leads to empty dst addresses
table _SKIPTO_DST_PREFIX_ create type addr
table _SKIPTO_DST_PREFIX_ add noc-sas-jump.yandex.net

:BEGIN
add allow ip from any to { table(_SKIPTO_DST_PREFIX_) or any }
"""
        self.EXPECT_TRUE(rules)

    def test_058_Prjid(self):
        rules = """
:BEGIN
add allow ip from any to { 640@2a02:6b8:c00::/40 }
add allow ip from any to { 10df426@2a02:6b8:c00::/40 }
add allow ip from any to { f800/21@2a02:6b8:c00::/40 }
"""
        self.EXPECT_TRUE(rules)

    def test_059_PrjidBadSyntax(self):
        rules = """
:BEGIN
add allow ip from any to { 100500640@2a02:6b8:c00::/40 }
"""
        self.EXPECT_FALSE(rules)

    def test_060_PrjidBadSyntax(self):
        rules = """
:BEGIN
add allow ip from any to { f800/0@2a02:6b8:c00::/40 }
"""
        self.EXPECT_FALSE(rules)

    def test_061_PrjidBadSyntax(self):
        rules = """
:BEGIN
add allow ip from any to { f800/128@2a02:6b8:c00::/40 }
"""
        self.EXPECT_FALSE(rules)

    @unittest.skip("do not support includes")
    def test_062_BadInclude(self):
        rules = """
:BEGIN
add allow ip from any to { 10.16.1.1 or 10.16.2.1 }
add allow ip from { 10.16.1.1 or 10.16.2.1 } to any
add skipto :ENDOFME ip from any to any

# exception if we can not open specified file
include "firewall.router-fw.m4.conf"
"""
        self.EXPECT_FALSE(rules)

    @unittest.skip("do not support includes")
    def test_063_BadInclude(self):
        rules = """
:BEGIN
add allow ip from any to { 10.16.1.1 or 10.16.2.1 }
add allow ip from { 10.16.1.1 or 10.16.2.1 } to any
add skipto :ENDOFME ip from any to any

# bad syntax
include "firewall.router-fw.m4.con
"""
        self.EXPECT_FALSE(rules)

    def test_064_ViaOptionsIn(self):
        rules = """
add skipto :VRF_MAX_IN ip from any to any { via lp.kni0.1694 or via lp.kni1.1694 } in
add deny ip from any to any
:VRF_MAX_IN
add count ip from any to any
"""
        self.EXPECT_TRUE(rules)

    def test_065_SkiptoDotDash(self):
        rules = """
add skipto :BEGIN-section.service ip from any to any
:BEGIN-section.service
add count ip from any to any
"""
        self.EXPECT_TRUE(rules)

# -------------------- fw-loader parser tests ----------------------
class TestFwLoaderParser(TestParserMethods):
    def test_001_tcp_icmptypes(self):
        rules = """
add allow tcp from any to any icmptypes 0,8
"""
        self.EXPECT_FALSE(rules)

    def test_002_udp_icmp6types(self):
        rules = """
add allow udp from any to any icmp6types 135,136
"""
        self.EXPECT_FALSE(rules)

    def test_003_ip4_icmp6types(self):
        rules = """
add allow ip4 from any to any icmp6types 135,136
"""
        self.EXPECT_FALSE(rules)

    def test_004_SrcPortOption(self):
        rules = """
add allow tcp from me to { 5.45.193.128/29 or 2a02:6b8:0:6::/64 or 95.108.136.200/29 } src-port 179
add allow tcp from any 179 to me
add allow udp from any src-port 53 to any
"""
        self.EXPECT_TRUE(rules)

    def test_005_DstPortOption(self):
        rules = """
add allow udp from { 5.45.193.128/29 or 2a02:6b8:0:6::/64 } to { 87.250.225.0/29 or 2a02:6b8:0:6::/64 } dst-port 3784,4784
add allow tcp from any to any 80,443
"""
        self.EXPECT_TRUE(rules)

    def test_006_DstPortOption(self):
        rules = """
# dst-port option is not allowed after src-statement
add allow udp from { 5.45.193.128/29 } dst-port 3784,4784 to { 95.108.136.200/29 }
"""
        self.EXPECT_FALSE(rules)

    def test_007_ProtoOption(self):
        rules = """
add allow ip from { 2a02:6b8::/32 } to { 2a02:6b8:b010:a0ff::/64 } proto ipencap in
add allow tag 653 ip4 from { 172.20.0.0/16 } to { 93.158.158.93 } { proto tcp or proto icmp or proto udp }
add allow ip from { 2a02:6b8:6666::/64 } to { 2a02:6b8::/32 } proto ipv6 out
add allow not ip4 from any to any in
"""
        self.EXPECT_TRUE(rules)

    def test_008_NamedPorts(self):
        rules = """
add allow udp from { 5.45.192.0/18 } bootpc,bootps to me bootps
"""
        self.EXPECT_TRUE(rules)

    def test_009_Comments(self):
        rules = """
# comment, empty comment, commented rule, rule's comments
#
# add allow ip from any to any src-port 53 dst-port 49152-65535
add skipto :ME_SECTION ip from me to any // ME_SECTION
add allow ip from any to { 5.45.195.136/29 } // TUN64_TO_DISK
:ME_SECTION
add allow ip6 from me to any
"""
        self.EXPECT_TRUE(rules)

    def test_010_NumericProtoOption(self):
        rules = """
add allow 17 from any to any
add allow ip from any to any proto 58
"""
        self.EXPECT_TRUE(rules)


if __name__ == '__main__':
    unittest.main()
