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
      }}

  ].

