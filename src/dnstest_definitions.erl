-module(dnstest_definitions).

-include("dns.hrl").

-export([definitions/0]).

definitions() ->
  [
    % 1	example.com.	IN	SOA	86400	ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
    % 2	.	IN	OPT	32768	
    % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='nxdomain.example.com.', qtype=ANY

    {any_nxdomain, {
        {question, {"nxdomain.example.com", ?DNS_TYPE_ANY}},
        {header, #dns_message{rc=?DNS_RCODE_NXDOMAIN, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, []},
            {authority, [
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {additional, [
                %{<<".">>, ?DNS_CLASS_IN, ?DNS_TYPE_OPT, 32768}
              ]}
          }}}},

    % 0	example.com.	IN	MX	120	10 smtp-servers.example.com.
    % 0	example.com.	IN	MX	120	15 smtp-servers.test.com.
    % 0	example.com.	IN	NS	120	ns1.example.com.
    % 0	example.com.	IN	NS	120	ns2.example.com.
    % 0	example.com.	IN	SOA	100000	ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
    % 2	.	IN	OPT	0	
    % 2	ns1.example.com.	IN	A	120	192.168.1.1
    % 2	ns2.example.com.	IN	A	120	192.168.1.2
    % 2	smtp-servers.example.com.	IN	A	120	192.168.0.2
    % 2	smtp-servers.example.com.	IN	A	120	192.168.0.3
    % 2	smtp-servers.example.com.	IN	A	120	192.168.0.4
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='example.com.', qtype=ANY

    {any_query, {
        {question, {"example.com", ?DNS_TYPE_ANY}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120, #dns_rrdata_mx{preference=10, exchange = <<"smtp-servers.example.com">>}},
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120, #dns_rrdata_mx{preference=15, exchange = <<"smtp-servers.test.com">>}},
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"ns1.example.com">>}},
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"ns2.example.com">>}},
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 100000, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {authority, []},
            {additional, [
                %{<<".">>, ?DNS_CLASS_IN, ?DNS_TYPE_OPT, 0},
                {<<"ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,1,1}}},
                {<<"ns2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,1,2}}},
                {<<"smtp-servers.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,0,2}}},
                {<<"smtp-servers.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,0,3}}},
                {<<"smtp-servers.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,0,4}}}
              ]}
          }}}},

    % 0	www.something.wtest.com.	IN	A	3600	4.3.2.1
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='www.something.wtest.com.', qtype=ANY

    {any_wildcard, {
        {question, {"www.something.wtest.com", ?DNS_TYPE_ANY}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"www.something.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{ip = {4,3,2,1}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % Test for A query for test.com in test.com. Should return an AA nodata, since
    % there is no A record there.

    % 1	test.com.	IN	SOA	3600	ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='test.com.', qtype=A

    {apex_level_a_but_no_a, {
        {question, {"test.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, []},
            {authority, [
                {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.test.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {additional, []}
          }}
      }},

    % Test for A query for wtest.com in wtest.com. Should return an AA A record.

    % 0	wtest.com.	IN	A	3600	9.9.9.9
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='wtest.com.', qtype=A

    {apex_level_a, {
        {question, {"wtest.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{ip = {9,9,9,9}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % Test for NS query for test.com IN NS blah.test.com at APEX level. Should
    % return AA.

    % 0	test.com.	IN	NS	3600	ns1.test.com.
    % 0	test.com.	IN	NS	3600	ns2.test.com.
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='test.com.', qtype=NS

    {apex_level_ns, {
        {question, {"test.com", ?DNS_TYPE_NS}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{dname = <<"ns1.test.com">>}},
                {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{dname = <<"ns2.test.com">>}}
              ]},
            {authority, []},
            {additional, [
                {<<"ns1.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{ip = {1,1,1,1}}},
                {<<"ns2.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{ip = {2,2,2,2}}}
              ]}
          }}
      }},

    % 0	outpost.example.com.	IN	A	120	192.168.2.1
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='outpost.example.com.', qtype=A

    {basic_a_resolution, {
        {question, {"outpost.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"outpost.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,2,1}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 0	ipv6.example.com.	IN	AAAA	120	2001:6a8:0:1:210:4bff:fe4b:4c61
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='ipv6.example.com.', qtype=AAAA

    {basic_aaaa_resolution, {
        {question, {"ipv6.example.com", ?DNS_TYPE_AAAA}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"ipv6.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_AAAA, 120, #dns_rrdata_aaaa{ip = {8193,1704,0,1,528,19455,65099,19553}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 0	hwinfo.example.com.	IN	HINFO	120	"abc" "def"
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='hwinfo.example.com.', qtype=HINFO

    {basic_hinfo, {
        {question, {"hwinfo.example.com", ?DNS_TYPE_HINFO}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"hwinfo.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_HINFO, 120, #dns_rrdata_hinfo{cpu = <<"abc">>, os = <<"def">>}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 0	location.example.com.	IN	LOC	120	51 56 0.123 N 5 54 0.000 E 4.00m 1.00m 10000.00m 10.00m
    % 0	location.example.com.	IN	LOC	120	51 56 1.456 S 5 54 0.000 E 4.00m 2.00m 10000.00m 10.00m
    % 0	location.example.com.	IN	LOC	120	51 56 2.789 N 5 54 0.000 W 4.00m 3.00m 10000.00m 10.00m
    % 0	location.example.com.	IN	LOC	120	51 56 3.012 S 5 54 0.000 W 4.00m 4.00m 10000.00m 10.00m
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='location.example.com.', qtype=LOC

    %{basic_loc, {
        %{question, {"location.example.com", ?DNS_TYPE_LOC}},
        %{header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %{records, {
            %{answers, [
                %{<<"location.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_LOC, 120, #dns_rrdata_loc{lat="51 56 0.123 N", lon="5 54 0.000 E", alt="4.00", size="1.00", horiz="10000.00", vert="10.00"}}
              %]},
            %{authority, []},
            %{additional, []}
          %}}
      %}},

    % 0	example.com.	IN	NS	120	ns1.example.com.
    % 0	example.com.	IN	NS	120	ns2.example.com.
    % 2	ns1.example.com.	IN	A	120	192.168.1.1
    % 2	ns2.example.com.	IN	A	120	192.168.1.2
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='example.com.', qtype=NS

    {basic_ns_resolution, {
        {question, {"example.com", ?DNS_TYPE_NS}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"ns1.example.com">>}},
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"ns2.example.com">>}}
              ]},
            {authority, []},
            {additional, [
                {<<"ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,1,1}}},
                {<<"ns2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,1,2}}}
              ]}
          }}
      }},

    % 0	example.com.	IN	SOA	100000	ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='example.com.', qtype=SOA

    {basic_soa_resolution, {
        {question, {"example.com", ?DNS_TYPE_SOA}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 100000, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 0	_ldap._tcp.dc.test.com.	IN	SRV	3600	0 100 389 server2.example.net.
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='_ldap._tcp.dc.test.com.', qtype=SRV

    {basic_srv_resolution, {
        {question, {"_ldap._tcp.dc.test.com", ?DNS_TYPE_SRV}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"_ldap._tcp.dc.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SRV, 3600, #dns_rrdata_srv{priority=0, weight=100, port=389, target= <<"server2.example.net">>}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 0	text.example.com.	IN	TXT	120	"Hi, this is some text"
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='text.example.com.', qtype=TXT

    {basic_txt_resolution, {
        {question, {"text.example.com", ?DNS_TYPE_TXT}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"text.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_TXT, 120, #dns_rrdata_txt{txt = [<<"Hi, this is some text">>]}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % If a CNAME wildcard is present, but there is also a direct hit for the qname
    % but not for the qtype, a NODATA response should ensue. This test runs at the
    % root of the domain (the 'apex')

    % 1	wtest.com.	IN	SOA	3600	ns1.wtest.com. ahu.example.com. 2005092501 28800 7200 604800 86400
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='secure.wtest.com.', qtype=A

    {cname_and_wildcard_at_root, {
        {question, {"secure.wtest.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, []},
            {authority, [
                {<<"wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.wtest.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {additional, []}
          }}
      }},

    % If a CNAME wildcard is present, but it points to a record that
    % does not have the requested type, a CNAME should be emitted plus a SOA to
    % indicate no match with the right record

    % 0	yo.test.test.com.	IN	CNAME	3600	server1.test.com.
    % 1	test.com.	IN	SOA	3600	ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='yo.test.test.com.', qtype=AAAA

    {cname_and_wildcard_but_no_correct_type, {
        {question, {"yo.test.test.com", ?DNS_TYPE_AAAA}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"yo.test.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 3600, #dns_rrdata_cname{dname = <<"server1.test.com">>}}
              ]},
            {authority, [
                {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.test.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {additional, []}
          }}
      }},

    % If a CNAME wildcard is present, but there is also a direct hit for the qname
    % but not for the qtype, a NODATA response should ensue.
    %
    % In this case www.test.test.com is an A record, but the query is for an MX.

    % 1	test.com.	IN	SOA	3600	ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='www.test.test.com.', qtype=MX

    {cname_and_wildcard, {
        {question, {"www.test.test.com", ?DNS_TYPE_MX}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, []},
            {authority, [
                {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.test.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {additional, []}
          }}
      }},

    % Tries to resolve the AAAA for www.example.com, which is a CNAME to
    % outpost.example.com, which has an A record, but no AAAA record. Should show
    % CNAME and SOA.

    % 0	www.example.com.	IN	CNAME	120	outpost.example.com.
    % 1	example.com.	IN	SOA	86400	ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='www.example.com.', qtype=AAAA

    {cname_but_no_correct_type, {
        {question, {"www.example.com", ?DNS_TYPE_AAAA}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"www.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"outpost.example.com">>}}
              ]},
            {authority, [
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {additional, []}
          }}
      }},

    % 0	loop1.example.com.	IN	CNAME	120	loop2.example.com.
    % 0	loop2.example.com.	IN	CNAME	120	loop3.example.com.
    % 0	loop3.example.com.	IN	CNAME	120	loop1.example.com.
    % Rcode: 2, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='loop1.example.com.', qtype=A

    {cname_loop_breakout, {
        {question, {"loop1.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_SERVFAIL, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"loop1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"loop2.example.com">>}},
                {<<"loop2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"loop3.example.com">>}},
                {<<"loop3.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"loop1.example.com">>}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % ANY query for a CNAME to a local NXDOMAIN.

    % 0	nxd.example.com.	IN	CNAME	120	nxdomain.example.com.
    % 2	.	IN	OPT	32768
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='nxd.example.com.', qtype=ANY

    {cname_to_nxdomain_any, {
        {question, {"nxd.example.com", ?DNS_TYPE_ANY}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"nxd.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"nxdomain.example.com">>}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % CNAME to a local NXDOMAIN.

    % 0	nxd.example.com.	IN	CNAME	120	nxdomain.example.com.
    % 1	example.com.	IN	SOA	86400	ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
    % 2	.	IN	OPT	32768
    % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='nxd.example.com.', qtype=A

    {cname_to_nxdomain, {
        {question, {"nxd.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"nxd.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"nxdomain.example.com">>}}
              ]},
            {authority, [
                {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {additional, []}
          }}
      }},

    % 0	server1.example.com.	IN	CNAME	120	server1.france.example.com.
    % 1	france.example.com.	IN	NS	120	ns1.otherprovider.net.
    % 1	france.example.com.	IN	NS	120	ns2.otherprovider.net.
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
    % Reply to question for qname='server1.example.com.', qtype=A

    {cname_to_referral, {
        {question, {"server1.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=false, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"server1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"server1.france.example.com">>}}
              ]},
            {authority, [
                {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"ns1.otherprovider.net">>}},
                {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"ns2.otherprovider.net">>}}
              ]},
            {additional, []}
          }}
      }},

    % 0	unauth.example.com.	IN	CNAME	120	no-idea.example.org.
    % 1	.	IN	NS	518400	a.root-servers.net.
    % 1	.	IN	NS	518400	b.root-servers.net.
    % 1	.	IN	NS	518400	c.root-servers.net.
    % 1	.	IN	NS	518400	d.root-servers.net.
    % 1	.	IN	NS	518400	e.root-servers.net.
    % 1	.	IN	NS	518400	f.root-servers.net.
    % 1	.	IN	NS	518400	g.root-servers.net.
    % 1	.	IN	NS	518400	h.root-servers.net.
    % 1	.	IN	NS	518400	i.root-servers.net.
    % 1	.	IN	NS	518400	j.root-servers.net.
    % 1	.	IN	NS	518400	k.root-servers.net.
    % 1	.	IN	NS	518400	l.root-servers.net.
    % 1	.	IN	NS	518400	m.root-servers.net.
    % 2	.	IN	OPT	32768
    % 2	a.root-servers.net.	IN	A	3600000	198.41.0.4
    % 2	b.root-servers.net.	IN	A	3600000	192.228.79.201
    % 2	c.root-servers.net.	IN	A	3600000	192.33.4.12
    % 2	d.root-servers.net.	IN	A	3600000	128.8.10.90
    % 2	e.root-servers.net.	IN	A	3600000	192.203.230.10
    % 2	f.root-servers.net.	IN	A	3600000	192.5.5.241
    % 2	g.root-servers.net.	IN	A	3600000	192.112.36.4
    % 2	h.root-servers.net.	IN	A	3600000	128.63.2.53
    % 2	i.root-servers.net.	IN	A	3600000	192.36.148.17
    % 2	j.root-servers.net.	IN	A	3600000	192.58.128.30
    % 2	k.root-servers.net.	IN	A	3600000	193.0.14.129
    % 2	l.root-servers.net.	IN	A	3600000	198.32.64.12
    % 2	m.root-servers.net.	IN	A	3600000	202.12.27.33
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='unauth.example.com.', qtype=ANY

    {cname_to_unauth_any, {
        {question, {"unauth.example.com", ?DNS_TYPE_ANY}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"unauth.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"no-idea.example.org">>}}
              ]},
            {authority, [
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"a.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"b.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"c.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"d.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"e.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"f.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"g.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"h.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"i.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"j.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"k.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"l.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"m.root-servers.net">>}}
              ]},
            {additional, [
                {<<"a.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {198,41,0,4}}},
                {<<"b.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,228,79,201}}},
                {<<"c.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,33,4,12}}},
                {<<"d.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {128,8,10,90}}},
                {<<"e.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,203,230,10}}},
                {<<"f.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,5,5,241}}},
                {<<"g.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,112,36,4}}},
                {<<"h.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {128,63,2,53}}},
                {<<"i.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,36,148,17}}},
                {<<"j.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,58,128,30}}},
                {<<"k.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {193,0,14,129}}},
                {<<"l.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {198,32,64,12}}},
                {<<"m.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {202,12,27,33}}}
              ]}
          }}
      }},

    % 0	unauth.example.com.	IN	CNAME	120	no-idea.example.org.
    % 1	.	IN	NS	518400	a.root-servers.net.
    % 1	.	IN	NS	518400	b.root-servers.net.
    % 1	.	IN	NS	518400	c.root-servers.net.
    % 1	.	IN	NS	518400	d.root-servers.net.
    % 1	.	IN	NS	518400	e.root-servers.net.
    % 1	.	IN	NS	518400	f.root-servers.net.
    % 1	.	IN	NS	518400	g.root-servers.net.
    % 1	.	IN	NS	518400	h.root-servers.net.
    % 1	.	IN	NS	518400	i.root-servers.net.
    % 1	.	IN	NS	518400	j.root-servers.net.
    % 1	.	IN	NS	518400	k.root-servers.net.
    % 1	.	IN	NS	518400	l.root-servers.net.
    % 1	.	IN	NS	518400	m.root-servers.net.
    % 2	.	IN	OPT	32768
    % 2	a.root-servers.net.	IN	A	3600000	198.41.0.4
    % 2	b.root-servers.net.	IN	A	3600000	192.228.79.201
    % 2	c.root-servers.net.	IN	A	3600000	192.33.4.12
    % 2	d.root-servers.net.	IN	A	3600000	128.8.10.90
    % 2	e.root-servers.net.	IN	A	3600000	192.203.230.10
    % 2	f.root-servers.net.	IN	A	3600000	192.5.5.241
    % 2	g.root-servers.net.	IN	A	3600000	192.112.36.4
    % 2	h.root-servers.net.	IN	A	3600000	128.63.2.53
    % 2	i.root-servers.net.	IN	A	3600000	192.36.148.17
    % 2	j.root-servers.net.	IN	A	3600000	192.58.128.30
    % 2	k.root-servers.net.	IN	A	3600000	193.0.14.129
    % 2	l.root-servers.net.	IN	A	3600000	198.32.64.12
    % 2	m.root-servers.net.	IN	A	3600000	202.12.27.33
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='unauth.example.com.', qtype=A

    {cname_to_unauth, {
        {question, {"unauth.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"unauth.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"no-idea.example.org">>}}
              ]},
            {authority, [
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"a.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"b.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"c.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"d.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"e.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"f.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"g.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"h.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"i.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"j.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"k.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"l.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"m.root-servers.net">>}}
              ]},
            {additional, [
                {<<"a.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {198,41,0,4}}},
                {<<"b.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,228,79,201}}},
                {<<"c.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,33,4,12}}},
                {<<"d.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {128,8,10,90}}},
                {<<"e.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,203,230,10}}},
                {<<"f.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,5,5,241}}},
                {<<"g.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,112,36,4}}},
                {<<"h.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {128,63,2,53}}},
                {<<"i.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,36,148,17}}},
                {<<"j.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,58,128,30}}},
                {<<"k.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {193,0,14,129}}},
                {<<"l.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {198,32,64,12}}},
                {<<"m.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {202,12,27,33}}}
              ]}
          }}
      }},

    % A five-long CNAME chain involving wildcards at every step

    % 0	start.example.com.	IN	CNAME	120	x.y.z.w1.example.com.
    % 0	x.y.z.w1.example.com.	IN	CNAME	120	x.y.z.w2.example.com.
    % 0	x.y.z.w2.example.com.	IN	CNAME	120	x.y.z.w3.example.com.
    % 0	x.y.z.w3.example.com.	IN	CNAME	120	x.y.z.w4.example.com.
    % 0	x.y.z.w4.example.com.	IN	CNAME	120	x.y.z.w5.example.com.
    % 0	x.y.z.w5.example.com.	IN	A	120	1.2.3.5
    % 2	.	IN	OPT	32768
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='start.example.com.', qtype=A

    {cname_wildcard_chain, {
        {question, {"start.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"start.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w1.example.com">>}},
                {<<"x.y.z.w1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w2.example.com">>}},
                {<<"x.y.z.w2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w3.example.com">>}},
                {<<"x.y.z.w3.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w4.example.com">>}},
                {<<"x.y.z.w4.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w5.example.com">>}},
                {<<"x.y.z.w5.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {1,2,3,5}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % If we CNAME to another locally-hosted domain, while following the chain,
    % we should make sure to update the left hand side too, even when hitting
    % a wildcard.

    % 0	bla.something.wtest.com.	IN	A	3600	4.3.2.1
    % 0	semi-external.example.com.	IN	CNAME	120	bla.something.wtest.com.
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='semi-external.example.com.', qtype=A

    {cross_domain_cname_to_wildcard, {
        {question, {"semi-external.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"semi-external.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"bla.something.wtest.com">>}},
                {<<"bla.something.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{ip = {4,3,2,1}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 0	www.something.wtest.com.	IN	A	3600	4.3.2.1
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='www.something.wtest.com.', qtype=A

    {direct_wildcard, {
        {question, {"www.something.wtest.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"www.something.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{ip = {4,3,2,1}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 0	_double._tcp.dc.test.com.	IN	SRV	3600	0 100 389 server1.test.com.
    % 0	_double._tcp.dc.test.com.	IN	SRV	3600	1 100 389 server1.test.com.
    % 2	server1.test.com.	IN	A	3600	1.2.3.4
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='_double._tcp.dc.test.com.', qtype=SRV

    {double_srv, {
        {question, {"_double._tcp.dc.test.com", ?DNS_TYPE_SRV}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"_double._tcp.dc.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SRV, 3600, #dns_rrdata_srv{priority=0, weight=100, port=389, target = <<"server1.test.com">>}},
                {<<"_double._tcp.dc.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SRV, 3600, #dns_rrdata_srv{priority=1, weight=100, port=389, target = <<"server1.test.com">>}}
              ]},
            {authority, []},
            {additional, []}
        }}
    }},

    % 0	double.example.com.	IN	A	120	192.168.5.1
    % 2	.	IN	OPT	32768
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='double.example.com.', qtype=A

    {double, {
        {question, {"double.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"double.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,5,1}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % A series of CNAME pointers can lead to an outside reference, which should be
    % passed in the Answer section. PowerDNS sends an unauthoritative NOERROR,
    % bind sends a SERVFAIL.

    % 0	external.example.com.	IN	CNAME	120	somewhere.else.net.
    % 1	.	IN	NS	518400	a.root-servers.net.
    % 1	.	IN	NS	518400	b.root-servers.net.
    % 1	.	IN	NS	518400	c.root-servers.net.
    % 1	.	IN	NS	518400	d.root-servers.net.
    % 1	.	IN	NS	518400	e.root-servers.net.
    % 1	.	IN	NS	518400	f.root-servers.net.
    % 1	.	IN	NS	518400	g.root-servers.net.
    % 1	.	IN	NS	518400	h.root-servers.net.
    % 1	.	IN	NS	518400	i.root-servers.net.
    % 1	.	IN	NS	518400	j.root-servers.net.
    % 1	.	IN	NS	518400	k.root-servers.net.
    % 1	.	IN	NS	518400	l.root-servers.net.
    % 1	.	IN	NS	518400	m.root-servers.net.
    % 2	a.root-servers.net.	IN	A	3600000	198.41.0.4
    % 2	b.root-servers.net.	IN	A	3600000	192.228.79.201
    % 2	c.root-servers.net.	IN	A	3600000	192.33.4.12
    % 2	d.root-servers.net.	IN	A	3600000	128.8.10.90
    % 2	e.root-servers.net.	IN	A	3600000	192.203.230.10
    % 2	f.root-servers.net.	IN	A	3600000	192.5.5.241
    % 2	g.root-servers.net.	IN	A	3600000	192.112.36.4
    % 2	h.root-servers.net.	IN	A	3600000	128.63.2.53
    % 2	i.root-servers.net.	IN	A	3600000	192.36.148.17
    % 2	j.root-servers.net.	IN	A	3600000	192.58.128.30
    % 2	k.root-servers.net.	IN	A	3600000	193.0.14.129
    % 2	l.root-servers.net.	IN	A	3600000	198.32.64.12
    % 2	m.root-servers.net.	IN	A	3600000	202.12.27.33
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='external.example.com.', qtype=A

    {external_cname_pointer, {
        {question, {"external.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"external.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"somewhere.else.net">>}}
              ]},
            {authority, [
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"a.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"b.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"c.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"d.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"e.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"f.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"g.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"h.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"i.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"j.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"k.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"l.root-servers.net">>}},
                {<<"">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 518400, #dns_rrdata_ns{dname = <<"m.root-servers.net">>}}
              ]},
            {additional, [
                {<<"a.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {198,41,0,4}}},
                {<<"b.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,228,79,201}}},
                {<<"c.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,33,4,12}}},
                {<<"d.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {128,8,10,90}}},
                {<<"e.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,203,230,10}}},
                {<<"f.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,5,5,241}}},
                {<<"g.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,112,36,4}}},
                {<<"h.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {128,63,2,53}}},
                {<<"i.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,36,148,17}}},
                {<<"j.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {192,58,128,30}}},
                {<<"k.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {193,0,14,129}}},
                {<<"l.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {198,32,64,12}}},
                {<<"m.root-servers.net">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600000, #dns_rrdata_a{ip = {202,12,27,33}}}
              ]}
          }}
      }},
     
    % 0	www.a.b.c.d.e.something.wtest.com.	IN	A	3600	4.3.2.1
    % 0	www.a.b.c.d.e.something.wtest.com.	IN	RRSIG	3600	A 8 3 3600 [expiry] [inception] [keytag] wtest.com. ...
    % 1	a.something.wtest.com.	IN	NSEC	86400	wtest.com. A RRSIG NSEC
    % 1	a.something.wtest.com.	IN	RRSIG	86400	NSEC 8 4 86400 [expiry] [inception] [keytag] wtest.com. ...
    % 2	.	IN	OPT	32768
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='www.a.b.c.d.e.something.wtest.com.', qtype=A

    {five_levels_wildcard_one_below_apex, {
        {question, {"www.a.b.c.d.e.something.wtest.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"www.a.b.c.d.e.something.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{ip = {4,3,2,1}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 0	www.a.b.c.d.e.wtest.com.	IN	A	3600	6.7.8.9
    % 0	www.a.b.c.d.e.wtest.com.	IN	RRSIG	3600	A 8 7 3600 [expiry] [inception] [keytag] wtest.com. ...
    % 1	*.a.b.c.d.e.wtest.com.	IN	NSEC	86400	ns1.wtest.com. A RRSIG NSEC
    % 1	*.a.b.c.d.e.wtest.com.	IN	RRSIG	86400	NSEC 8 7 86400 [expiry] [inception] [keytag] wtest.com. ...
    % 2	.	IN	OPT	32768
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='www.a.b.c.d.e.wtest.com.', qtype=A

    {five_levels_wildcard, {
        {question, {"www.a.b.c.d.e.wtest.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"www.a.b.c.d.e.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{ip = {6,7,8,9}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % Verify that asking for A of a glue record returns a referral.

    % 1	usa.example.com.	IN	NS	120	usa-ns1.usa.example.com.
    % 1	usa.example.com.	IN	NS	120	usa-ns2.usa.example.com.
    % 2	usa-ns1.usa.example.com.	IN	A	120	192.168.4.1
    % 2	usa-ns2.usa.example.com.	IN	A	120	192.168.4.2
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
    % Reply to question for qname='usa-ns2.usa.example.com.', qtype=A

    {glue_record, {
        {question, {"usa-ns2.usa.example.com", ?DNS_TYPE_A}},
        {header,  #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=false, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, []},
            {authority, [
                {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"usa-ns1.usa.example.com">>}},
                {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"usa-ns2.usa.example.com">>}}
              ]},
            {additional, [
                {<<"usa-ns1.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,4,1}}},
                {<<"usa-ns2.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,4,2}}}
              ]}
          }}
      }},

    % When something.example.com is delegated to NS records that reside *within*
    % something.example.com, glue is needed. The IP addresses of the relevant NS
    % records should then be provided in the additional section.

    % 1	usa.example.com.	IN	NS	120	usa-ns1.usa.example.com.
    % 1	usa.example.com.	IN	NS	120	usa-ns2.usa.example.com.
    % 2	usa-ns1.usa.example.com.	IN	A	120	192.168.4.1
    % 2	usa-ns2.usa.example.com.	IN	A	120	192.168.4.2
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
    % Reply to question for qname='www.usa.example.com.', qtype=A

    {glue_referral, {
        {question, {"www.usa.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=false, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, []},
            {authority, [
                {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"usa-ns1.usa.example.com">>}},
                {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"usa-ns2.usa.example.com">>}}
              ]},
            {additional, [
                {<<"usa-ns1.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,4,1}}},
                {<<"usa-ns2.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,4,2}}}
              ]}
          }}
      }},

    % 1	italy.example.com.	IN	NS	120	italy-ns1.example.com.
    % 1	italy.example.com.	IN	NS	120	italy-ns2.example.com.
    % 2	italy-ns1.example.com.	IN	A	120	192.168.5.1
    % 2	italy-ns2.example.com.	IN	A	120	192.168.5.2
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
    % Reply to question for qname='www.italy.example.com.', qtype=A

    {internal_referral, {
        {question, {"www.italy.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=false, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, []},
            {authority, [
                {<<"italy.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"italy-ns1.example.com">>}},
                {<<"italy.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{dname = <<"italy-ns2.example.com">>}}
              ]},
            {additional, [
                {<<"italy-ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,5,1}}},
                {<<"italy-ns2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,5,2}}}
              ]}
          }}
      }},

    % 1	test.com.	IN	SOA	3600	ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
    % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test.com.', qtype=TXT

    {long_name, {
        {question, {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test.com", ?DNS_TYPE_TXT}},
        {header, #dns_message{rc=?DNS_RCODE_NXDOMAIN, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, []},
            {authority, [
                {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.test.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {additional, []}
          }}
      }},

    % 0	start1.example.com.	IN	CNAME	120	start2.example.com.
    % 0	start2.example.com.	IN	CNAME	120	start3.example.com.
    % 0	start3.example.com.	IN	CNAME	120	start4.example.com.
    % 0	start4.example.com.	IN	A	120	192.168.2.2
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='start1.example.com.', qtype=A

    {multi_step_cname_resolution, {
        {question, {"start1.example.com", ?DNS_TYPE_A}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"start1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"start2.example.com">>}},
                {<<"start2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"start3.example.com">>}},
                {<<"start3.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"start4.example.com">>}},
                {<<"start4.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,2,2}}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 0	escapedtext.example.com.	IN	TXT	120	"begin" "the \"middle\" p\\art" "the end"
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='escapedtext.example.com.', qtype=TXT

    {multi_txt_escape_resolution, {
        {question, {"escapedtext.example.com", ?DNS_TYPE_TXT}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, [
                {<<"escapedtext.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_TXT, 120, #dns_rrdata_txt{txt = [<<"begin">>,<<"the \"middle\" p\\art">>, <<"the end">>]}}
              ]},
            {authority, []},
            {additional, []}
          }}
      }},

    % 1	wtest.com.	IN	SOA	3600	ns1.wtest.com. ahu.example.com. 2005092501 28800 7200 604800 86400
    % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
    % Reply to question for qname='www.something.wtest.com.', qtype=TXT

    {wrong_type_wildcard, {
        {question, {"www.something.wtest.com", ?DNS_TYPE_TXT}},
        {header, #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        {records, {
            {answers, []},
            {authority, [
                {<<"wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.wtest.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
              ]},
            {additional, []}
          }}
      }}

  ].

