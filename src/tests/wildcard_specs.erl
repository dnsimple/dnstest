-module(wildcard_specs).

-include_lib("dns_erlang/include/dns.hrl").

-export([definitions/0]).

%% @doc Return all Wildcard test definitions
-spec definitions() -> [dnstest:definition()].
definitions() ->
    [
        % 0  www.something.wtest.com.  IN  A  3600  4.3.2.1
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.something.wtest.com.', qtype=ANY

        {any_wildcard, #{
            question => {~"www.something.wtest.com", ?DNS_TYPE_ANY},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"www.something.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{
                        ip = {4, 3, 2, 1}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % Wildcard bounded in A record
        {wildcard_bounded, #{
            question => {~"b.c.d.cover.wtest.com", ?DNS_TYPE_ANY},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"b.c.d.cover.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{
                        ip = {1, 2, 3, 4}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % If a CNAME wildcard is present, but there is also a direct hit for the qname
        % but not for the qtype, a NODATA response should ensue. This test runs at the
        % root of the domain (the 'apex')

        % 1  wtest.com.  IN  SOA  3600  ns1.wtest.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='secure.wtest.com.', qtype=A

        {cname_and_wildcard_at_root, #{
            question => {~"secure.wtest.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [],
                authority => [
                    {<<"wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{
                        mname = <<"ns1.wtest.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2005092501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % If a CNAME wildcard is present, but it points to a record that
        % does not have the requested type, a CNAME should be emitted plus a SOA to
        % indicate no match with the right record

        % 0  yo.test.test.com.  IN  CNAME  3600  server1.test.com.
        % 1  test.com.  IN  SOA  3600  ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='yo.test.test.com.', qtype=AAAA

        {cname_and_wildcard_but_no_correct_type, #{
            question => {~"yo.test.test.com", ?DNS_TYPE_AAAA},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"yo.test.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 3600,
                        #dns_rrdata_cname{dname = <<"server1.test.com">>}}
                ],
                authority => [
                    {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 300, #dns_rrdata_soa{
                        mname = <<"ns1.test.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 1728543606,
                        refresh = 86400,
                        retry = 7200,
                        expire = 604800,
                        minimum = 300
                    }}
                ],
                additional => []
            }
        }},

        % If a CNAME wildcard is present, but there is also a direct hit for the qname
        % but not for the qtype, a NODATA response should ensue.
        %
        % In this case www.test.test.com is an A record, but the query is for an MX.

        % 1  test.com.  IN  SOA  3600  ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.test.test.com.', qtype=MX

        {cname_and_wildcard, #{
            question => {~"www.test.test.com", ?DNS_TYPE_MX},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [],
                authority => [
                    {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 300, #dns_rrdata_soa{
                        mname = <<"ns1.test.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 1728543606,
                        refresh = 86400,
                        retry = 7200,
                        expire = 604800,
                        minimum = 300
                    }}
                ],
                additional => []
            }
        }},

        % A five-long CNAME chain involving wildcards at every step

        % 0  start.example.com.  IN  CNAME  120  x.y.z.w1.example.com.
        % 0  x.y.z.w1.example.com.  IN  CNAME  120  x.y.z.w2.example.com.
        % 0  x.y.z.w2.example.com.  IN  CNAME  120  x.y.z.w3.example.com.
        % 0  x.y.z.w3.example.com.  IN  CNAME  120  x.y.z.w4.example.com.
        % 0  x.y.z.w4.example.com.  IN  CNAME  120  x.y.z.w5.example.com.
        % 0  x.y.z.w5.example.com.  IN  A  120  1.2.3.5
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='start.example.com.', qtype=A

        {cname_wildcard_chain, #{
            question => {~"start.example.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"start.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"x.y.z.w1.example.com">>}},
                    {<<"x.y.z.w1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"x.y.z.w2.example.com">>}},
                    {<<"x.y.z.w2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"x.y.z.w3.example.com">>}},
                    {<<"x.y.z.w3.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"x.y.z.w4.example.com">>}},
                    {<<"x.y.z.w4.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"x.y.z.w5.example.com">>}},
                    {<<"x.y.z.w5.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {1, 2, 3, 5}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % If we CNAME to another locally-hosted domain, return only the CNAME. Resolvers
        % will take care of further resolution.

        % 0  semi-external.example.com.  IN  CNAME  120  bla.something.wtest.com.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='semi-external.example.com.', qtype=A

        {cross_domain_cname_to_wildcard, #{
            question => {~"semi-external.example.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"semi-external.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{
                            dname = <<"bla.something.wtest.com">>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  www.something.wtest.com.  IN  A  3600  4.3.2.1
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.something.wtest.com.', qtype=A

        {direct_wildcard, #{
            question => {~"www.something.wtest.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"www.something.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{
                        ip = {4, 3, 2, 1}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  www.a.b.c.d.e.something.wtest.com.  IN  A  3600  4.3.2.1
        % 0  www.a.b.c.d.e.something.wtest.com.  IN  RRSIG  3600  A 8 3 3600 [expiry] [inception] [keytag] wtest.com. ...
        % 1  a.something.wtest.com.  IN  NSEC  86400  wtest.com. A RRSIG NSEC
        % 1  a.something.wtest.com.  IN  RRSIG  86400  NSEC 8 4 86400 [expiry] [inception] [keytag] wtest.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.a.b.c.d.e.something.wtest.com.', qtype=A

        {five_levels_wildcard_one_below_apex, #{
            question => {~"www.a.b.c.d.e.something.wtest.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"www.a.b.c.d.e.something.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600,
                        #dns_rrdata_a{ip = {4, 3, 2, 1}}}
                ],
                authority => [],
                additional => []
            }
        }},

        % If there is a more-specific subtree that matches part of a name,
        % a less-specific wildcard cannot match it.

        % 1  wtest.com.  IN  SOA  3600  ns1.wtest.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.a.something.wtest.com.', qtype=A

        {obscured_wildcard, #{
            question => {~"www.a.something.wtest.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NXDOMAIN,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [],
                authority => [
                    {<<"wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{
                        mname = <<"ns1.wtest.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2005092501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % 1  sub.test.test.com.  IN  NS  3600  ns-test.example.net.test.com.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='www.sub.test.test.com.', qtype=A

        {wildcard_overlaps_delegation, #{
            question => {~"www.sub.test.test.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = false,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [],
                authority => [
                    {<<"sub.test.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns-test.example.net.test.com">>
                    }}
                ],
                additional => []
            }
        }},

        % 1  wtest.com.  IN  SOA  3600  ns1.wtest.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.something.wtest.com.', qtype=TXT

        {wrong_type_wildcard, #{
            question => {~"www.something.wtest.com", ?DNS_TYPE_TXT},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [],
                authority => [
                    {<<"wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{
                        mname = <<"ns1.wtest.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2005092501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        {cname_wildcard_cover, #{
            question => {~"www.cover.wtest.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"www.cover.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 3600,
                        #dns_rrdata_cname{
                            dname = <<"proxy.cover.wtest.com">>
                        }},
                    {<<"proxy.cover.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{
                        ip = {1, 2, 3, 4}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % Ensure wildcard chaining with DNSSEC works.
        % In erldns the wildcard matched response are signed on the fly.
        {cname_wildcard_chain_dnssec, #{
            question => {~"start.minimal-dnssec.com", ?DNS_TYPE_A},
            additional => [#dns_optrr{dnssec = true}],
            transport => tcp,
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"start.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{
                            dname = <<"x.y.z.w1.minimal-dnssec.com">>
                        }},
                    {<<"start.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 120,
                            expiration = 0,
                            inception = 0,
                            keytag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"x.y.z.w1.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{
                            dname = <<"x.y.z.w2.minimal-dnssec.com">>
                        }},
                    {<<"x.y.z.w1.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 6,
                            original_ttl = 120,
                            expiration = 0,
                            inception = 0,
                            keytag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"x.y.z.w2.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{
                            dname = <<"x.y.z.w3.minimal-dnssec.com">>
                        }},
                    {<<"x.y.z.w2.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 6,
                            original_ttl = 120,
                            expiration = 0,
                            inception = 0,
                            keytag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"x.y.z.w3.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{
                            dname = <<"x.y.z.w4.minimal-dnssec.com">>
                        }},
                    {<<"x.y.z.w3.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 6,
                            original_ttl = 120,
                            expiration = 0,
                            inception = 0,
                            keytag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"x.y.z.w4.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{
                            dname = <<"x.y.z.w5.minimal-dnssec.com">>
                        }},
                    {<<"x.y.z.w4.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 6,
                            original_ttl = 120,
                            expiration = 0,
                            inception = 0,
                            keytag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"x.y.z.w5.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {1, 2, 3, 5}}},
                    {<<"x.y.z.w5.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_A,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 6,
                            original_ttl = 120,
                            expiration = 0,
                            inception = 0,
                            keytag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }}
    ].
