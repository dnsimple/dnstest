-module(ent_specs).

-include_lib("dns_erlang/include/dns.hrl").

-export([definitions/0]).

%% @doc Return all the ENT (Empty Non-Terminal) test definitions
%% Empty Non-Terminal nodes are domain names that exist but don't have records directly
%% associated with them, yet have children underneath them in the DNS tree
-spec definitions() -> [dnstest:definition()].
definitions() ->
    [
        %% ENT basic - Queries to empty non-terminal nodes should return SOA in authority section
        {ent, #{
            question => {~"c.test.com", ?DNS_TYPE_A},
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

        %% ENT ANY - Querying for ANY on ENT nodes should also return SOA in authority section
        {ent_any, #{
            question => {~"c.test.com", ?DNS_TYPE_ANY},
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

        %% SOA queries to ENTs should get the zone's SOA
        {ent_soa, #{
            question => {~"c.test.com", ?DNS_TYPE_SOA},
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

        %% Testing RR that is enclosed in ENTs
        {ent_rr_enclosed_in_ent, #{
            question => {~"b.c.test.com", ?DNS_TYPE_TXT},
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

        %% Testing NSEC RR that is enclosed in ENTs
        {ent_rr_enclosed_in_ent_nsec, #{
            question => {~"b.c.test.com", ?DNS_TYPE_TXT},
            additional => [#dns_optrr{udp_payload_size = 1232, dnssec = true}],
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
                    }},
                    {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 300, #dns_rrdata_rrsig{
                        type_covered = ?DNS_TYPE_SOA,
                        alg = ?DNS_ALG_RSASHA256,
                        labels = 2,
                        original_ttl = 3600,
                        expiration = 0,
                        inception = 0,
                        keytag = 0,
                        signers_name = <<"test.com">>,
                        signature = <<>>
                    }},
                    {<<"b.c.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 300, #dns_rrdata_nsec{
                        next_dname = <<"\000.b.c.test.com">>,
                        types = [?DNS_TYPE_A, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]
                    }},
                    {<<"b.c.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 300, #dns_rrdata_rrsig{
                        type_covered = ?DNS_TYPE_NSEC,
                        alg = ?DNS_ALG_RSASHA256,
                        labels = 4,
                        original_ttl = 300,
                        expiration = 0,
                        inception = 0,
                        keytag = 0,
                        signers_name = <<"test.com">>,
                        signature = <<>>
                    }}
                ],
                additional => []
            }
        }},

        %% With DNSSEC, ENTs should not have NXNAME in the bitmap
        {nsec_nxname_ent, #{
            question => {~"ent1.minimal-dnssec.com", ?DNS_TYPE_AAAA},
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
                answers => [],
                authority => [
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 300
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            keytag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"ent1.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400,
                        #dns_rrdata_nsec{
                            next_dname = <<"\000.ent1.minimal-dnssec.com">>,
                            types = [?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]
                        }},
                    {<<"ent1.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_NSEC,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 86400,
                            expiration = 0,
                            inception = 0,
                            keytag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                additional => []
            }
        }},

        %% Wildcard below an ENT
        {ent_wildcard_below_ent, #{
            question => {~"something.a.b.c.test.com", ?DNS_TYPE_A},
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
                    {<<"something.a.b.c.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600,
                        #dns_rrdata_a{ip = {8, 7, 6, 5}}}
                ],
                authority => [],
                additional => []
            }
        }}
    ].
