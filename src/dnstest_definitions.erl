-module(dnstest_definitions).

-include_lib("dns_erlang/include/dns.hrl").

-export([definitions/0]).
-export([pdns_definitions/0, pdns_dnssec_definitions/0]).
-export([erldns_definitions/0, erldns_dnssec_definitions/0]).

-elvis([
    {elvis_text_style, line_length, #{ignore => [dnstest_definitions]}}
]).

-spec definitions() -> [dnstest:definition()].
definitions() ->
    pdns_definitions() ++
        erldns_definitions() ++
        pdns_dnssec_definitions() ++
        erldns_dnssec_definitions().

-spec erldns_definitions() -> [dnstest:definition()].
erldns_definitions() ->
    [
        {ns_zonecut, #{
            question => {"child.zonecut.example.com", ?DNS_TYPE_MX},
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
                    {<<"zonecut.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns1.cutwithzonecut.com">>
                    }},
                    {<<"zonecut.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns2.cutwithzonecut.com">>
                    }}
                ],
                additional => []
            }
        }},

        {ns_zonecut_child_cname, #{
            question => {"cname.zonecut.example.com", ?DNS_TYPE_CNAME},
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
                    {<<"zonecut.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns1.cutwithzonecut.com">>
                    }},
                    {<<"zonecut.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns2.cutwithzonecut.com">>
                    }}
                ],
                additional => []
            }
        }},
        {ns_recursion_breakout, #{
            question => {"rns.example.com", ?DNS_TYPE_NS},
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
                    {<<"rns.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"rns.example.com">>
                    }}
                ],
                additional => [
                    {<<"rns.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 7, 3}
                    }}
                ]
            }
        }},

        {ns_a_record, #{
            question => {"ns1.example.com", ?DNS_TYPE_A},
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
                    {<<"ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 1, 1}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        {ns_aaaa_record, #{
            question => {"ns1.example.com", ?DNS_TYPE_AAAA},
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
                    {<<"ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_AAAA, 120, #dns_rrdata_aaaa{
                        ip = {8193, 3512, 34211, 0, 0, 35374, 880, 29492}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        {cname_case, #{
            question => {"WWW.example.com", ?DNS_TYPE_CNAME},
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
                    {<<"WWW.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{
                        dname = <<"outpost.example.com">>
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        {cname_wildcard_cover, #{
            question => {"www.cover.wtest.com", ?DNS_TYPE_A},
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

        {caa_record, #{
            question => {"caa.example.com", ?DNS_TYPE_CAA},
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
                    {<<"caa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CAA, 3600, #dns_rrdata_caa{
                        flags = 0, tag = <<"issue">>, value = <<"example.net">>
                    }}
                ],
                authority => [],
                additional => []
            }
        }}
    ].

-spec erldns_dnssec_definitions() -> [dnstest:definition()].
erldns_dnssec_definitions() ->
    [
        {dnssec_soa, #{
            question => {"minimal-dnssec.com", ?DNS_TYPE_SOA},
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
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        {dnssec_ns, #{
            question => {"minimal-dnssec.com", ?DNS_TYPE_NS},
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
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns1.example.com">>
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns2.example.com">>
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_NS,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => [
                    {<<"ns1.example.com">>, 1, 1, 120, #dns_rrdata_a{ip = {192, 168, 1, 1}}},
                    {<<"ns1.example.com">>, 1, 28, 120, #dns_rrdata_aaaa{
                        ip = {8193, 3512, 34211, 0, 0, 35374, 880, 29492}
                    }},
                    {<<"ns2.example.com">>, 1, 1, 120, #dns_rrdata_a{ip = {192, 168, 1, 2}}}
                ]
            }
        }},

        {dnssec_a, #{
            question => {"real-a.minimal-dnssec.com", ?DNS_TYPE_A},
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
                    {<<"real-a.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600,
                        #dns_rrdata_a{ip = {192, 168, 1, 10}}},
                    {<<"real-a.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_A,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        {dnssec_a_with_udp_payload_size, #{
            question => {"real-a.minimal-dnssec.com", ?DNS_TYPE_A},
            additional => [#dns_optrr{udp_payload_size = 1230, dnssec = true}],
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
                    {<<"real-a.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600,
                        #dns_rrdata_a{ip = {192, 168, 1, 10}}},
                    {<<"real-a.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_A,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        {dnssec_cname, #{
            question => {"www.minimal-dnssec.com", ?DNS_TYPE_CNAME},
            additional => [#dns_optrr{dnssec = true}],
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
                    {<<"www.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 3600,
                        #dns_rrdata_cname{
                            dname = <<"real-a.minimal-dnssec.com">>
                        }},
                    {<<"www.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        {dnssec_follow_cname, #{
            question => {"www.minimal-dnssec.com", ?DNS_TYPE_A},
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
                    {<<"www.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 3600,
                        #dns_rrdata_cname{
                            dname = <<"real-a.minimal-dnssec.com">>
                        }},
                    {<<"www.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"real-a.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600,
                        #dns_rrdata_a{ip = {192, 168, 1, 10}}},
                    {<<"real-a.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_A,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        {dnssec_cds, #{
            question => {"minimal-dnssec.com", ?DNS_TYPE_CDS},
            additional => [#dns_optrr{dnssec = true}],
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
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CDS, 3600, #dns_rrdata_cds{
                        keytag = 7709,
                        alg = 8,
                        digest_type = 2,
                        digest =
                            <<38, 78, 31, 224, 37, 157, 234, 188, 253, 222, 111, 63, 200, 191, 44,
                                4, 230, 236, 88, 78, 153, 130, 79, 157, 55, 215, 48, 167, 34, 227,
                                225, 145>>
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CDS,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 1479123419,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        {dnssec_cdnskey, #{
            question => {"minimal-dnssec.com", ?DNS_TYPE_CDNSKEY},
            additional => [#dns_optrr{dnssec = true}],
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
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CDNSKEY, 3600,
                        #dns_rrdata_cdnskey{
                            flags = 257,
                            protocol = 3,
                            alg = ?DNS_ALG_RSASHA256,
                            public_key = dnstest_harness:decode_dnskey_public_key(
                                <<"AwEAAbk0RRaXNYo0Z/8B24QelHa/CedMRxO68qSPHjisJETLzSEO7E36",
                                    "ZZpLWZghsPAbxkqf1ipAmihUCnT6gTs/aZz01XIiewiaYgmiUEUPbOiy",
                                    "SC+mDy5LnOB/0+Z6HsBUrJxC9jT/VIVpEYqeRvyWFMu+5ry0nIm4ZiZK",
                                    "DcMYZ7ZXDQ3vqwrZKACGhTEMmCIvbzD0SUv4G19jMJxR6xovev8=">>
                            ),
                            key_tag = 7709
                        }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CDNSKEY,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        {dnssec_dnskey, #{
            question => {"minimal-dnssec.com", ?DNS_TYPE_DNSKEY},
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
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY, 3600,
                        #dns_rrdata_dnskey{
                            flags = 257,
                            protocol = 3,
                            alg = ?DNS_ALG_RSASHA256,
                            public_key = <<>>,
                            key_tag = 0
                        }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY, 3600,
                        #dns_rrdata_dnskey{
                            flags = 256,
                            protocol = 3,
                            alg = ?DNS_ALG_RSASHA256,
                            public_key = <<>>,
                            key_tag = 0
                        }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_DNSKEY,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % Ensure the correct NSEC result when the zone is present but the qname is not.
        {nsec_name, #{
            question => {"a.minimal-dnssec.com", ?DNS_TYPE_A},
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
                        minimum = 86400
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 20250701022432,
                            inception = 20250402022432,
                            key_tag = 27123,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature =
                                <<"YHRxn+lwC/bQ9Nur148Z29WPm6nqSPxXsHQ+oNtBGy9SNDvVtG08EtMc pPJCHOna0JY3+NtjIGCvO3LmJlfRH+2GD22arRMDZMx0mZAbpVziyzMl //3UEpGZNScS9s77iTYeFQJtVfI8mpyVAltZPisMeCEDiwzNzzD5a+iK 5O8=">>
                        }},
                    {<<"a.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400,
                        #dns_rrdata_nsec{
                            next_dname = <<"\000.a.minimal-dnssec.com">>,
                            types = [?DNS_TYPE_AAAA, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]
                        }},
                    {<<"a.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_NSEC,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 86400,
                            expiration = 20250701022432,
                            inception = 20250402022432,
                            key_tag = 27123,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature =
                                <<"a4jqiLpodikx5CeT/jCMCjct/8tEku++xaOz6F0kFZpgJ3K2gQvv2ZlV la/nAr4tedWODPxRDFxdiZBUCaZa3oHId0kVzIHhUdnljmfzUmssn5MB 5UVgPRYTtGIJP2a48SLwQNRtdOVS/5YF0ixhXeCItPn1wJ14f47aRPFX Fo4=">>
                        }}
                ],
                additional => []
            }
        }},

        % Ensure the correct NSEC result when the zone is present but the qname is not.
        {nsec_name_mixed_case, #{
            question => {"a.Minimal-dnssec.com", ?DNS_TYPE_A},
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
                    {<<"Minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }},
                    {<<"Minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 20250701022432,
                            inception = 20250402022432,
                            key_tag = 27123,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature =
                                <<"ZwhobjkUbO2gLHv8nnYMJbM80+wTxYagnP26e5WIDg9L9rtd4FfWfuXE e7YA6LXP3g4Fo/VRujbk3KVgVLj3sRbc2WRnlP+yef8l6rG4q5IjuocB WBliUTV1mUjaOL2EGmuix65cxP7UK2WCUcTFVvEB8u22vnc4tr5nrnc5 Ljw=">>
                        }},
                    {<<"a.Minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400,
                        #dns_rrdata_nsec{
                            next_dname = <<"\000.a.minimal-dnssec.com">>,
                            types = [?DNS_TYPE_AAAA, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]
                        }},
                    {<<"a.Minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_NSEC,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 86400,
                            expiration = 20250701022432,
                            inception = 20250402022432,
                            key_tag = 27123,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature =
                                <<"b/ki+sptUkfNm2RzJi40PS01nslxNZUQokKq666sqOW3ARslmkUvTW7X j8f3OK2k9FbE17Z2E81Bp2LMzihATFZiPBdnKl9dggzK9q+RLAm+Ok17 7QLWrLWSGiubc0hS9Lt8LNBGIXLYUSMmEQkF/YeLbMkx2MtzVs9qLkJ+ Vfo=">>
                        }}
                ],
                additional => []
            }
        }},

        % Ensure the correct NSEC result when the qname matches but the qtype does not.
        {nsec_type, #{
            question => {"minimal-dnssec.com", ?DNS_TYPE_A},
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
                        minimum = 86400
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400,
                        #dns_rrdata_nsec{
                            next_dname = <<"\000.minimal-dnssec.com">>,
                            types = [
                                ?DNS_TYPE_NS,
                                ?DNS_TYPE_SOA,
                                ?DNS_TYPE_MX,
                                ?DNS_TYPE_TXT,
                                ?DNS_TYPE_RRSIG,
                                ?DNS_TYPE_NSEC,
                                ?DNS_TYPE_DNSKEY,
                                ?DNS_TYPE_CDS,
                                ?DNS_TYPE_CDNSKEY,
                                ?DNS_TYPE_SPF,
                                ?DNS_TYPE_CAA
                            ]
                        }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_NSEC,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 86400,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                additional => []
            }
        }},

        % Ensure the correct NSEC result when zone is present but the qname is not, and the qtype is ANY.
        {nsec_name_any, #{
            question => {"ab.minimal-dnssec.com", ?DNS_TYPE_ANY},
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
                        minimum = 86400
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 1751336672,
                            inception = 1743560672,
                            key_tag = 27123,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"ab.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400,
                        #dns_rrdata_nsec{
                            next_dname = <<"\000.ab.minimal-dnssec.com">>,
                            types = [?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_NXNAME]
                        }},
                    {<<"ab.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_NSEC,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 86400,
                            expiration = 1751336672,
                            inception = 1743560672,
                            key_tag = 27123,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                additional => []
            }
        }},

        % Verify NXNAME query
        % https://www.ietf.org/archive/id/draft-ietf-dnsop-compact-denial-of-existence-07.html#section-3.5
        {nxname_query, #{
            question => {"nxname.minimal-dnssec.com", ?DNS_TYPE_NXNAME},
            additional => [#dns_optrr{dnssec = true}],
            transport => tcp,
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_FORMERR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [],
                authority => [],
                additional => []
            }
        }},

        % Verify NSEC bitmap correctly has NXNAME (TYPE128) in the event that label is NXDOMAIN
        {nsec_nxname, #{
            question => {"nxname.minimal-dnssec.com", ?DNS_TYPE_AAAA},
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
                        minimum = 86400
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"nxname.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400,
                        #dns_rrdata_nsec{
                            next_dname = <<"\000.nxname.minimal-dnssec.com">>,
                            types = [?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_NXNAME]
                        }},
                    {<<"nxname.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_NSEC,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 86400,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                additional => []
            }
        }},

        % Verify NXNAME not present in ENT response
        {nsec_nxname_ent, #{
            question => {"ent1.minimal-dnssec.com", ?DNS_TYPE_AAAA},
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
                        minimum = 86400
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
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
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                additional => []
            }
        }},

        % Verify NSEC RR Type bitmap is correct
        {nsec_rr_type_bitmap_wildcard, #{
            question => {"nosuch.something.minimal-dnssec.com", ?DNS_TYPE_AAAA},
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
                        minimum = 86400
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }},
                    {<<"nosuch.something.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC,
                        86400, #dns_rrdata_nsec{
                            next_dname = <<"\000.nosuch.something.minimal-dnssec.com">>,
                            types = [?DNS_TYPE_A, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]
                        }},
                    {<<"nosuch.something.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG,
                        86400, #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_NSEC,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 4,
                            original_ttl = 86400,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                additional => []
            }
        }},

        {cname_to_nxdomain_dnssec, #{
            question => {"nxd.minimal-dnssec.com", ?DNS_TYPE_A},
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
                    {<<"nxd.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 3600,
                        #dns_rrdata_cname{
                            dname = <<"nxdomain.minimal-dnssec.com">>
                        }},
                    {<<"nxd.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_SOA,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                additional => []
            }
        }},

        % Ensure wildcard chaining with DNSSEC works.
        % In erldns the wildcard matched response are signed on the fly.
        {cname_wildcard_chain_dnssec, #{
            question => {"start.minimal-dnssec.com", ?DNS_TYPE_A},
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
                            key_tag = 0,
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
                            key_tag = 0,
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
                            key_tag = 0,
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
                            key_tag = 0,
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
                            key_tag = 0,
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
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }}
    ].

-spec pdns_dnssec_definitions() -> [dnstest:definition()].
pdns_dnssec_definitions() ->
    [
        % 1  example.com.  IN  NSEC  86400  double.example.com. NS SOA MX RRSIG NSEC DNSKEY
        % 1  example.com.  IN  RRSIG  86400  NSEC 8 2 86400 [expiry] [inception] [keytag] example.com. ...
        % 1  example.com.  IN  RRSIG  86400  SOA 8 2 100000 [expiry] [inception] [keytag] example.com. ...
        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % 1  nxd.example.com.  IN  NSEC  86400  outpost.example.com. CNAME RRSIG NSEC
        % 1  nxd.example.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='nxdomain.example.com.', qtype=ANY

        %{any_nxdomain_dnssec, {
        %question => {"nxdomain.example-dnssec.com", ?DNS_TYPE_ANY}},
        %header => #dns_message{rc=?DNS_RCODE_NXDOMAIN, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => []},
        %authority => [
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}},
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_SOA, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 100000, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example.com">>, signature = 0}},
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"double.example.com">>, types = [?DNS_TYPE_NS, ?DNS_TYPE_SOA, ?DNS_TYPE_MX, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_DNSKEY]}},
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example.com">>, signature = 0}},
        %{<<"nxd.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"outpost.example.com">>, types = [?DNS_TYPE_CNAME, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %{<<"nxd.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example.com">>, signature = 0}}
        %]},
        %additional => []
        %}}}},

        % 0  www.something.wtest.com.  IN  A  3600  4.3.2.1
        % 0  www.something.wtest.com.  IN  RRSIG  3600  A 8 3 3600 [expiry] [inception] [keytag] wtest.com. ...
        % 1  a.something.wtest.com.  IN  NSEC  86400  wtest.com. A RRSIG NSEC
        % 1  a.something.wtest.com.  IN  RRSIG  86400  NSEC 8 4 86400 [expiry] [inception] [keytag] wtest.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.something.wtest.com.', qtype=ANY

        %{any_wildcard_dnssec, {
        %question => {"www.something.wtest-dnssec.com", ?DNS_TYPE_ANY}},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => [
        %{<<"www.something.wtest-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{ip = {4,3,2,1}}},
        %{<<"www.something.wtest-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_A, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 3600, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"wtest-dnssec.com">>, signature = 0}}
        %]},
        %authority => [
        %{<<"a.something.wtest-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"wtest-dnssec.com">>, types = [?DNS_TYPE_A, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %{<<"a.something.wtest-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 4, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"wtest-dnssec.com">>, signature = 0}}
        %]},
        %additional => []
        %}}
        %}},

        % 0  nxd.example.com.  IN  CNAME  120  nxdomain.example.com.
        % 0  nxd.example.com.  IN  RRSIG  120  CNAME 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 1  example.com.  IN  NSEC  86400  double.example.com. NS SOA MX RRSIG NSEC DNSKEY
        % 1  example.com.  IN  RRSIG  86400  NSEC 8 2 86400 [expiry] [inception] [keytag] example.com. ...
        % 1  example.com.  IN  RRSIG  86400  SOA 8 2 100000 [expiry] [inception] [keytag] example.com. ...
        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % 1  nxd.example.com.  IN  NSEC  86400  outpost.example.com. CNAME RRSIG NSEC
        % 1  nxd.example.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='nxd.example.com.', qtype=A

        %{cname_to_nxdomain_dnssec, {
        %question => {"nxd.example-dnssec.com", ?DNS_TYPE_A}},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => [
        %{<<"nxd.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"nxdomain.example-dnssec.com">>}},
        %{<<"nxd.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_CNAME, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 120, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}}
        %]},
        %authority => [
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{mname = <<"ns1.example-dnssec.com">>, rname = <<"ahu.example-dnssec.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}},
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_SOA, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 100000, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"double.example-dnssec.com">>, types = [?DNS_TYPE_NS, ?DNS_TYPE_SOA, ?DNS_TYPE_MX, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_DNSKEY]}},
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %{<<"nxd.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"outpost.example-dnssec.com">>, types = [?DNS_TYPE_CNAME, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %{<<"nxd.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}}
        %]},
        %additional => []
        %}}
        %}},

        % 0  nxd.example.com.  IN  CNAME  120  nxdomain.example.com.
        % 0  nxd.example.com.  IN  RRSIG  120  CNAME 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='nxd.example.com.', qtype=ANY

        {cname_to_nxdomain_any_dnssec, #{
            question => {"nxd.minimal-dnssec.com", ?DNS_TYPE_ANY},
            additional => [#dns_optrr{dnssec = true}],
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
                    {<<"nxd.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 3600,
                        #dns_rrdata_cname{
                            dname = <<"nxdomain.minimal-dnssec.com">>
                        }},
                    {<<"nxd.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0 unauth.example.com.  IN  CNAME  120  no-idea.example.org.
        % 0  unauth.example.com.  IN  RRSIG  120  CNAME 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='unauth.example.com.', qtype=ANY

        {cname_to_unauth_any_dnssec, #{
            question => {"unauth.minimal-dnssec.com", ?DNS_TYPE_ANY},
            additional => [#dns_optrr{dnssec = true}],
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
                    {<<"unauth.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{
                            dname = <<"no-idea.example.org">>
                        }},
                    {<<"unauth.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 120,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  unauth.example.com.  IN  CNAME  120  no-idea.example.org.
        % 0  unauth.example.com.  IN  RRSIG  120  CNAME 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='unauth.example.com.', qtype=A

        {cname_to_unauth_dnssec, #{
            question => {"unauth.minimal-dnssec.com", ?DNS_TYPE_A},
            additional => [#dns_optrr{dnssec = true}],
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
                    {<<"unauth.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{
                            dname = <<"no-idea.example.org">>
                        }},
                    {<<"unauth.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_CNAME,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 120,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  start.example.com.  IN  CNAME  120  x.y.z.w1.example.com.
        % 0  start.example.com.  IN  RRSIG  120  CNAME 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 0  x.y.z.w1.example.com.  IN  CNAME  120  x.y.z.w2.example.com.
        % 0  x.y.z.w1.example.com.  IN  RRSIG  120  CNAME 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 0  x.y.z.w2.example.com.  IN  CNAME  120  x.y.z.w3.example.com.
        % 0  x.y.z.w2.example.com.  IN  RRSIG  120  CNAME 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 0  x.y.z.w3.example.com.  IN  CNAME  120  x.y.z.w4.example.com.
        % 0  x.y.z.w3.example.com.  IN  RRSIG  120  CNAME 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 0  x.y.z.w4.example.com.  IN  CNAME  120  x.y.z.w5.example.com.
        % 0  x.y.z.w4.example.com.  IN  RRSIG  120  CNAME 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 0  x.y.z.w5.example.com.  IN  A  120  1.2.3.5
        % 0  x.y.z.w5.example.com.  IN  RRSIG  120  A 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 1  *.w1.example.com.  IN  NSEC  86400  *.w2.example.com. CNAME RRSIG NSEC
        % 1  *.w1.example.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] example.com. ...
        % 1  *.w2.example.com.  IN  NSEC  86400  *.w3.example.com. CNAME RRSIG NSEC
        % 1  *.w2.example.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] example.com. ...
        % 1  *.w3.example.com.  IN  NSEC  86400  *.w4.example.com. CNAME RRSIG NSEC
        % 1  *.w3.example.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] example.com. ...
        % 1  *.w4.example.com.  IN  NSEC  86400  *.w5.example.com. CNAME RRSIG NSEC
        % 1  *.w4.example.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] example.com. ...
        % 1  *.w5.example.com.  IN  NSEC  86400  www.example.com. A RRSIG NSEC
        % 1  *.w5.example.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='start.example.com.', qtype=A

        %{cname_wildcard_chain_dnssec, {
        %question => {"start.example-dnssec.com", ?DNS_TYPE_A},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => [
        %{<<"start.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w1.example-dnssec.com">>}},
        %{<<"start.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_CNAME, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 120, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %{<<"x.y.z.w1.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w2.example-dnssec.com">>}},
        %{<<"x.y.z.w1.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_CNAME, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 120, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %{<<"x.y.z.w2.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w3.example-dnssec.com">>}},
        %{<<"x.y.z.w2.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_CNAME, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 120, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %{<<"x.y.z.w3.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w4.example-dnssec.com">>}},
        %{<<"x.y.z.w3.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_CNAME, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 120, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %{<<"x.y.z.w4.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{dname = <<"x.y.z.w5.example-dnssec.com">>}},
        %{<<"x.y.z.w4.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_CNAME, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 120, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %{<<"x.y.z.w5.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {1,2,3,5}}},
        %{<<"x.y.z.w5.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_A, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 120, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}}
        %]},
        %authority => [
        %%{<<"*.w1.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"*.w2.example-dnssec.com">>, types = [?DNS_TYPE_CNAME, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %%{<<"*.w1.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %%{<<"*.w2.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"*.w3.exaexample-dnssecle.com">>, types = [?DNS_TYPE_CNAME, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %%{<<"*.w2.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %%{<<"*.w3.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"*.w4.example-dnssec.com">>, types = [?DNS_TYPE_CNAME, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %%{<<"*.w3.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %%{<<"*.w4.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"*.w5.example-dnssec.com">>, types = [?DNS_TYPE_CNAME, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %%{<<"*.w4.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %%{<<"*.w5.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"www.example-dnssec.com">>, types = [?DNS_TYPE_A, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %%{<<"*.w5.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}}
        %]},
        %additional => []
        %}}
        %}},

        % minimal-dnssec.com.  3600  IN  RRSIG  DNSKEY 8 2 3600 20250701022432 20250402022432 7709 minimal-dnssec.com. ftamO2KppO1zevAzJGhQwXiuJTkwm0hCLG0NWNyMXQjZnC+fKqUtV6xV vTGSHbxPOk+g4S7zNrJnhyn3xKLe8EAsNq9pFc1g4/evxjKMNBroIRm1 p4F0bhCIGSOWruP07W5i3ir0YOk3qCeVhybwpB8itlSU06CIBKeoU4ro GgUjfk0WlOxoIOmo+3QW2ziwOPX2M7DJPcLuwnOnz3aPrg==
        % minimal-dnssec.com.  3600  IN  DNSKEY  256 3 8 AwEAAdIqMYlTELLVzA8yP7FHshb0e+Kojr2IIjtCgpk4hspMtSJyavOm qT7fRu2FgzY5mo++FVLdkMd1+8Yj8I5bbnCWayA5kQgwY7HtFur1He19 i0ps5IZ2i+2XopOlmi2Zdob/RK4sYAw3G3t3ji8t6RMwLdsljNp+KDJU 59cVMRH9
        % minimal-dnssec.com.  3600  IN  DNSKEY  257 3 8 AwEAAbk0RRaXNYo0Z/8B24QelHa/CedMRxO68qSPHjisJETLzSEO7E36 ZZpLWZghsPAbxkqf1ipAmihUCnT6gTs/aZz01XIiewiaYgmiUEUPbOiy SC+mDy5LnOB/0+Z6HsBUrJxC9jT/VIVpEYqeRvyWFMu+5ry0nIm4ZiZK DcMYZ7ZXDQ3vqwrZKACGhTEMmCIvbzD0SUv4G19jMJxR6xovev8=
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='example.com.', qtype=DNSKEY

        {direct_dnskey_dnssec, #{
            question => {"minimal-dnssec.com", ?DNS_TYPE_DNSKEY},
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
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY, 3600,
                        #dns_rrdata_dnskey{
                            flags = 257,
                            protocol = 3,
                            alg = ?DNS_ALG_RSASHA256,
                            public_key = <<>>,
                            key_tag = 0
                        }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY, 3600,
                        #dns_rrdata_dnskey{
                            flags = 256,
                            protocol = 3,
                            alg = ?DNS_ALG_RSASHA256,
                            public_key = <<>>,
                            key_tag = 0
                        }},
                    {<<"minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_DNSKEY,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 2,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 2  .  IN  OPT  32768
        % Rcode: 5, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='example.com.', qtype=RRSIG
        % erldns rejects direct RRSIG queries

        {direct_rrsig, #{
            question => {"minimal-dnssec.com", ?DNS_TYPE_RRSIG},
            additional => [#dns_optrr{dnssec = true}],
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_REFUSED,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = false,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [],
                authority => [],
                additional => []
            }
        }},

        % 0  double.example.com.  IN  A  120  192.168.5.1
        % 0  double.example.com.  IN  RRSIG  120  A 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='double.example.com.', qtype=A

        % Verify that we deduplicate records correctly for RRSIG generation.
        {double_dnssec, #{
            question => {"double.minimal-dnssec.com", ?DNS_TYPE_A},
            additional => [#dns_optrr{dnssec = true}],
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
                    {<<"double.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600,
                        #dns_rrdata_a{ip = {192, 168, 5, 1}}},
                    {<<"double.minimal-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600,
                        #dns_rrdata_rrsig{
                            type_covered = ?DNS_TYPE_A,
                            alg = ?DNS_ALG_RSASHA256,
                            labels = 3,
                            original_ttl = 3600,
                            expiration = 0,
                            inception = 0,
                            key_tag = 0,
                            signers_name = <<"minimal-dnssec.com">>,
                            signature = <<>>
                        }}
                ],
                authority => [],
                additional => []
            }
        }}

        % 1  example.com.  IN  NSEC  86400  double.example.com. NS SOA MX RRSIG NSEC DNSKEY
        % 1  example.com.  IN  RRSIG  86400  NSEC 8 2 86400 [expiry] [inception] [keytag] example.com. ...
        % 1  example.com.  IN  RRSIG  86400  SOA 8 2 100000 [expiry] [inception] [keytag] example.com. ...
        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='example.com.', qtype=DS

        %{ds_at_apex_noerror_dnssec, {
        %question => {"example-dnssec.com", ?DNS_TYPE_DS},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => []},
        %authority => [
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{mname = <<"ns1.example-dnssec.com">>, rname = <<"ahu.example-dnssec.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}},
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_SOA, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 100000, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}},
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"double.example-dnssec.com">>, types = [?DNS_TYPE_NS, ?DNS_TYPE_SOA, ?DNS_TYPE_MX, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_DNSKEY]}},
        %{<<"example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example-dnssec.com">>, signature = 0}}
        %]},
        %additional => []
        %}}
        %}}

        % 0  secure-delegated.dnssec-parent.com.  IN  DS  3600  54319 8 2 a0b9c38cd324182af0ef66830d0a0e85a1d58979c9834e18c871779e040857b7
        % 0  secure-delegated.dnssec-parent.com.  IN  RRSIG  3600  DS 8 3 3600 [expiry] [inception] [keytag] dnssec-parent.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='secure-delegated.dnssec-parent.com.', qtype=DS

        %{ds_at_both_sides_dnssec, {
        %question => {"secure-delegated.dnssec-parent.com", ?DNS_TYPE_DS},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => [
        %{<<"secure-delegated.dnssec-parent.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_DS, 3600, #dns_rrdata_ds{keytag = 54319, alg = 8, digest_type = 2, digest = hex_to_bin(<<"a0b9c38cd324182af0ef66830d0a0e85a1d58979c9834e18c871779e040857b7">>)}},
        %{<<"secure-delegated.dnssec-parent.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_DS, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 3600, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"dnssec-parent.com">>, signature = 0}}
        %]},
        %authority => []},
        %additional => []
        %}}
        %}},

        % This test tries to resolve a DS question at a secure delegation.
        % It was written specifically to verify that we do not sign NS response
        % at secure delegations.

        % 0  dsdelegation.example.com.  IN  DS  120  28129 8 1 caf1eaaecdabe7616670788f9022454bf5fd9fda
        % 0  dsdelegation.example.com.  IN  RRSIG  120  DS 8 3 120 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='dsdelegation.example.com.', qtype=DS

        %{ds_at_secure_delegation, {
        %question => {"dsdelegation.example-dnssec.com", ?DNS_TYPE_DS},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => [
        %{<<"dsdelegation.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_DS, 120, #dns_rrdata_ds{keytag = 28129, alg = 8, digest_type = 1, digest = hex_to_bin(<<"CAF1EAAECDABE7616670788F9022454BF5FD9FDA">>)}},
        %{<<"dsdelegation.example-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 120, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_DS, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 120, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example.com">>, signature = 0}}
        %]},
        %authority => []},
        %additional => []
        %}}
        %}}

        % This test tries to resolve a DS question at an unsecure delegation.

        % 1  example.com.  IN  RRSIG  86400  SOA 8 2 100000 [expiry] [inception] [keytag] example.com. ...
        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % 1  usa.example.com.  IN  NSEC  86400  *.w1.example.com. NS RRSIG NSEC
        % 1  usa.example.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='usa.example.com.', qtype=DS

        %{ds_at_unsecure_delegation, {
        %question => {"usa.example.com", ?DNS_TYPE_DS},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => []},
        %authority => [
        %{<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}},
        %{<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_SOA, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 100000, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example.com">>, signature = 0}},
        %{<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"*.w1.example.com">>, types = [?DNS_TYPE_NS, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %{<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example.com">>, signature = 0}}
        %]},
        %additional => []
        %}}
        %}}

        % 1  delegated.dnssec-parent.com.  IN  NSEC  86400  ns1.dnssec-parent.com. NS RRSIG NSEC
        % 1  delegated.dnssec-parent.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] dnssec-parent.com. ...
        % 1  dnssec-parent.com.  IN  RRSIG  3600  SOA 8 2 3600 [expiry] [inception] [keytag] dnssec-parent.com. ...
        % 1  dnssec-parent.com.  IN  SOA  3600  ns1.dnssec-parent.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='delegated.dnssec-parent.com.', qtype=DS

        %{ds_at_unsecure_zone_cut, {
        %question => {"delegated.dnssec-parent.com", ?DNS_TYPE_DS},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => []},
        %authority => [
        %{<<"dnssec-parent.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}},
        %{<<"dnssec-parent.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 3600, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_SOA, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 3600, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"example.com">>, signature = 0}},

        %{<<"delegated.dnssec-parent.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"ns1.dnssec-parent.com">>, types = [?DNS_TYPE_NS, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %{<<"delegated.dnssec-parent.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"dnssec-parent.com">>, signature = 0}}
        %]},
        %additional => []
        %}}
        %}}

        % TODO: ds_inside_delegation

        % 1  blah.test.com.  IN  NSEC  86400  b.c.test.com. NS RRSIG NSEC
        % 1  blah.test.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] test.com. ...
        % 1  test.com.  IN  RRSIG  3600  SOA 8 2 3600 [expiry] [inception] [keytag] test.com. ...
        % 1  test.com.  IN  SOA  3600  ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='c.test.com.', qtype=ANY

        % Currently broken in erl-dns because the TTL in the RRSIG is 3600 instead of 84600

        %{ent_any_dnssec, {
        %question => {"c.test-dnssec.com", ?DNS_TYPE_ANY},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => []},
        %authority => [
        %{<<"test-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.test-dnssec.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}},
        %{<<"test-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_SOA, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 3600, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"test.com">>, signature = 0}},
        %{<<"blah.test-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"b.c.test-dnssec.com">>, types = [?DNS_TYPE_NS, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}},
        %{<<"blah.test-dnssec.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, alg = ?DNS_ALG_RSASHA256, labels = 3, original_ttl = 86400, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"test-dnssec.com">>, signature = 0}}
        %]},
        %additional => []
        %}}
        %}}

        % Minimal zone (only NS response) Make sure existent hosts without proper type
        % generates a correct NSEC denial.

        % 1  minimal.com.  IN  NSEC  86400  minimal.com. NS SOA RRSIG NSEC DNSKEY

        %{minimal_noerror, {
        %question => {<<"minimal.com">>, ?DNS_TYPE_TXT},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => [
        %{<<"mimimal.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}},
        %{<<"minimal.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RRSIG, 86400, #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_SOA, alg = ?DNS_ALG_RSASHA256, labels = 2, original_ttl = 3600, expiration = 0, inception = 0, key_tag = 0, signers_name = <<"minimal.com">>, signature = 0}},
        %{<<"minimal.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"minimal.com">>, types = [?DNS_TYPE_NS, ?DNS_TYPE_SOA, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_DNSKEY]}}
        %]},
        %authority => []},
        %additional => []
        %}}
        %}}

        % Minimal zone (only NS response) Make sure non-existent hosts generates a correct
        % NSEC denial.

        % 1  minimal.com.  IN  NSEC  86400  minimal.com. NS SOA RRSIG NSEC DNSKEY

        %{minimal_nxdomain, {
        %question => {<<"a.minimal.com">>, ?DNS_TYPE_A},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=false, oc=?DNS_OPCODE_QUERY}},
        %additional => [#dns_optrr{dnssec=true}]},
        %response => #{
        %answers => [
        %{<<"minimal.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NSEC, 86400, #dns_rrdata_nsec{next_dname = <<"minimal.com">>, types = [?DNS_TYPE_NS, ?DNS_TYPE_SOA, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_DNSKEY]}}
        %]},
        %authority => []},
        %additional => []
        %}}
        %}}

        % This tests determines if multi-segment NSEC response work.

        % 0  hightype.example.com.  IN  NSEC  86400  host-0.example.com. A RRSIG NSEC TYPE65534
        % 0  hightype.example.com.  IN  RRSIG  86400  NSEC 8 3 86400 [expiry] [inception] [keytag] example.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='hightype.example.com.', qtype=NSEC

        % TODO: nsec-bitmap

        % TODO: nsec-glue-at-delegation
        % TODO: nsec-glue
        % TODO: nsec-middle
        % TODO: nsec-wildcard
        % TODO: nsec-wraparound
        % TODO: nsec-wrong-type-at-apex
        % TODO: nsec-wrong-type
        % TODO: nsecx-mode2-wildcard-nodata
        % TODO: nsecx-mode3-wildcard
        % TODO: nxdomain-below-nonempty-terminal
        % TODO: nxdomain-for-unknown-record

        % TODO: second-level-nxdomain
        % TODO: secure-delegation-ds-ns
        % TODO: secure-delegation
        % TODO: space-name

        % TODO: two-level-nxdomain
        % TODO: underscore-sorting

        % TODO: uppercase-nsec
    ].

-spec pdns_definitions() -> [dnstest:definition()].
pdns_definitions() ->
    [
        % 0  aland.test.com.  IN  TXT  3600  "\195\133LAND ISLANDS"
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='aland.test.com.', qtype=TXT

        {'8_bit_txt', #{
            question => {"aland.test.com", ?DNS_TYPE_TXT},
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
                    {<<"aland.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_TXT, 3600, #dns_rrdata_txt{
                        txt = [<<"\\195\\133LAND ISLANDS">>]
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='nxdomain.example.com.', qtype=ANY

        {any_nxdomain, #{
            question => {"nxdomain.example.com", ?DNS_TYPE_ANY},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % ;; ANSWER SECTION:
        % example.com.    120  IN  NS  ns1.example.com.
        % example.com.    120  IN  NS  ns2.example.com.
        % example.com.    100000  IN  SOA  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % example.com.    120  IN  MX  10 smtp-servers.example.com.
        % example.com.    120  IN  MX  15 smtp-servers.test.com.

        % ;; ADDITIONAL SECTION:
        % ns1.example.com.  120  IN  A  192.168.1.1
        % ns1.example.com.  120  IN  AAAA  2001:db8:85a3::8a2e:370:7334
        % ns2.example.com.  120  IN  A  192.168.1.2
        % smtp-servers.example.com. 120  IN  A  192.168.0.2
        % smtp-servers.example.com. 120  IN  A  192.168.0.3
        % smtp-servers.example.com. 120  IN  A  192.168.0.4
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='example.com.', qtype=ANY

        {any_query, #{
            question => {"example.com", ?DNS_TYPE_ANY},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120, #dns_rrdata_mx{
                        preference = 10,
                        exchange = <<"smtp-servers.example.com">>
                    }},
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120, #dns_rrdata_mx{
                        preference = 15,
                        exchange = <<"smtp-servers.test.com">>
                    }},
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns1.example.com">>
                    }},
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns2.example.com">>
                    }},
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 100000, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                authority => [],
                additional => [
                    {<<"ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 1, 1}
                    }},
                    {<<"ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_AAAA, 120, #dns_rrdata_aaaa{
                        ip = {8193, 3512, 34211, 0, 0, 35374, 880, 29492}
                    }},
                    {<<"ns2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 1, 2}
                    }},
                    {<<"smtp-servers.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                            ip = {192, 168, 0, 2}
                        }},
                    {<<"smtp-servers.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                            ip = {192, 168, 0, 3}
                        }},
                    {<<"smtp-servers.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 0, 4}
                    }}
                ]
            }
        }},

        % 0  www.something.wtest.com.  IN  A  3600  4.3.2.1
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.something.wtest.com.', qtype=ANY

        {any_wildcard, #{
            question => {"www.something.wtest.com", ?DNS_TYPE_ANY},
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

        % Test for A query for test.com in test.com. Should return an AA nodata, since
        % there is no A record there.

        % 1  test.com.  IN  SOA  3600  ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='test.com.', qtype=A

        {apex_level_a_but_no_a, #{
            question => {"test.com", ?DNS_TYPE_A},
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

        % Test for A query for wtest.com in wtest.com. Should return an AA A record.

        % 0  wtest.com.  IN  A  3600  9.9.9.9
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='wtest.com.', qtype=A

        {apex_level_a, #{
            question => {"wtest.com", ?DNS_TYPE_A},
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
                    {<<"wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{
                        ip = {9, 9, 9, 9}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % Test for NS query for test.com IN NS blah.test.com at APEX level. Should
        % return AA.
        % ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44220
        % ;; flags: qr aa rd; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1
        % ;; WARNING: recursion requested but not available

        % ;; OPT PSEUDOSECTION:
        % ; EDNS: version: 0, flags:; udp: 4096
        % ;; QUESTION SECTION:
        % ;test.com.      IN  NS

        % ;; ANSWER SECTION:
        % test.com.    3600  IN  NS  ns1.dnsimple.com.
        % test.com.    3600  IN  NS  ns2.dnsimple-edge.net.
        % test.com.    3600  IN  NS  ns3.dnsimple.com.
        % test.com.    3600  IN  NS  ns4.dnsimple-edge.org.
        % Reply to question for qname='test.com.', qtype=NS

        {apex_level_ns, #{
            question => {"test.com", ?DNS_TYPE_NS},
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
                    {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns1.dnsimple.com">>
                    }},
                    {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns2.dnsimple-edge.net">>
                    }},
                    {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns3.dnsimple.com">>
                    }},
                    {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns4.dnsimple-edge.org">>
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  outpost.example.com.  IN  A  120  192.168.2.1
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='outpost.example.com.', qtype=A

        {basic_a_resolution, #{
            question => {"outpost.example.com", ?DNS_TYPE_A},
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
                    {<<"outpost.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 2, 1}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  ipv6.example.com.  IN  AAAA  120  2001:6a8:0:1:210:4bff:fe4b:4c61
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='ipv6.example.com.', qtype=AAAA

        {basic_aaaa_resolution, #{
            question => {"ipv6.example.com", ?DNS_TYPE_AAAA},
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
                    {<<"ipv6.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_AAAA, 120, #dns_rrdata_aaaa{
                        ip = {8193, 1704, 0, 1, 528, 19455, 65099, 19553}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  hwinfo.example.com.  IN  HINFO  120  "abc" "def"
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='hwinfo.example.com.', qtype=HINFO

        {basic_hinfo, #{
            question => {"hwinfo.example.com", ?DNS_TYPE_HINFO},
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
                    {<<"hwinfo.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_HINFO, 120,
                        #dns_rrdata_hinfo{cpu = <<"abc">>, os = <<"def">>}}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  location.example.com.  IN  LOC  120  51 56 0.123 N 5 54 0.000 E 4.00m 1.00m 10000.00m 10.00m
        % 0  location.example.com.  IN  LOC  120  51 56 1.456 S 5 54 0.000 E 4.00m 2.00m 10000.00m 10.00m
        % 0  location.example.com.  IN  LOC  120  51 56 2.789 N 5 54 0.000 W 4.00m 3.00m 10000.00m 10.00m
        % 0  location.example.com.  IN  LOC  120  51 56 3.012 S 5 54 0.000 W 4.00m 4.00m 10000.00m 10.00m
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='location.example.com.', qtype=LOC

        %{basic_loc, {
        %question => {"location.example.com", ?DNS_TYPE_LOC},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %response => #{
        %answers => [
        %{<<"location.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_LOC, 120, #dns_rrdata_loc{lat="51 56 0.123 N", lon="5 54 0.000 E", alt="4.00", size="1.00", horiz="10000.00", vert="10.00"}}
        %]},
        %authority => []},
        %additional => []
        %}}
        %}},

        % 0  example.com.  IN  NS  120  ns1.example.com.
        % 0  example.com.  IN  NS  120  ns2.example.com.
        % 2  ns1.example.com.  IN  A  120  192.168.1.1
        % 2 ns1.example.com.        IN      AAAA    120     2001:0db8:85a3:0000:0000:8a2e:0370:7334
        % 2  ns2.example.com.  IN  A  120  192.168.1.2
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='example.com.', qtype=NS

        {basic_ns_resolution, #{
            question => {"example.com", ?DNS_TYPE_NS},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns1.example.com">>
                    }},
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns2.example.com">>
                    }}
                ],
                authority => [],
                additional => [
                    {<<"ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 1, 1}
                    }},
                    {<<"ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_AAAA, 120, #dns_rrdata_aaaa{
                        ip = {8193, 3512, 34211, 0, 0, 35374, 880, 29492}
                    }},
                    {<<"ns2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 1, 2}
                    }}
                ]
            }
        }},

        % 0  example.com.  IN  SOA  100000  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='example.com.', qtype=SOA

        {basic_soa_resolution, #{
            question => {"example.com", ?DNS_TYPE_SOA},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 100000, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  _ldap._tcp.dc.test.com.  IN  SRV  3600  0 100 389 server2.example.net.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='_ldap._tcp.dc.test.com.', qtype=SRV

        {basic_srv_resolution, #{
            question => {"_ldap._tcp.dc.test.com", ?DNS_TYPE_SRV},
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
                    {<<"_ldap._tcp.dc.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SRV, 3600,
                        #dns_rrdata_srv{
                            priority = 0,
                            weight = 100,
                            port = 389,
                            target = <<"server2.example.net">>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  text.example.com.  IN  TXT  120  "Hi, this is some text"
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='text.example.com.', qtype=TXT

        {basic_txt_resolution, #{
            question => {"text.example.com", ?DNS_TYPE_TXT},
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
                    {<<"text.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_TXT, 120, #dns_rrdata_txt{
                        txt = [<<"Hi, this is some text">>]
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
            question => {"secure.wtest.com", ?DNS_TYPE_A},
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
            question => {"yo.test.test.com", ?DNS_TYPE_AAAA},
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
            question => {"www.test.test.com", ?DNS_TYPE_MX},
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

        % Tries to resolve the AAAA for www.example.com, which is a CNAME to
        % outpost.example.com, which has an A record, but no AAAA record. Should show
        % CNAME and SOA.

        % 0  www.example.com.  IN  CNAME  120  outpost.example.com.
        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.example.com.', qtype=AAAA

        {cname_but_no_correct_type, #{
            question => {"www.example.com", ?DNS_TYPE_AAAA},
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
                    {<<"www.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{
                        dname = <<"outpost.example.com">>
                    }}
                ],
                authority => [
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % 0  loop1.example.com.  IN  CNAME  120  loop2.example.com.
        % 0  loop2.example.com.  IN  CNAME  120  loop3.example.com.
        % 0  loop3.example.com.  IN  CNAME  120  loop1.example.com.
        % Rcode: 2, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='loop1.example.com.', qtype=A

        {cname_loop_breakout, #{
            question => {"loop1.example.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_SERVFAIL,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"loop1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"loop2.example.com">>}},
                    {<<"loop2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"loop3.example.com">>}},
                    {<<"loop3.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"loop1.example.com">>}}
                ],
                authority => [],
                additional => []
            }
        }},

        % ANY query for a CNAME to a local NXDOMAIN.

        % 0  nxd.example.com.  IN  CNAME  120  nxdomain.example.com.
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='nxd.example.com.', qtype=ANY

        {cname_to_nxdomain_any, #{
            question => {"nxd.example.com", ?DNS_TYPE_ANY},
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
                    {<<"nxd.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{
                        dname = <<"nxdomain.example.com">>
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % CNAME to a local NXDOMAIN.

        % 0  nxd.example.com.  IN  CNAME  120  nxdomain.example.com.
        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='nxd.example.com.', qtype=A

        {cname_to_nxdomain, #{
            question => {"nxd.example.com", ?DNS_TYPE_A},
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
                    {<<"nxd.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{
                        dname = <<"nxdomain.example.com">>
                    }}
                ],
                authority => [
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % 0  server1.example.com.  IN  CNAME  120  server1.france.example.com.
        % 1  france.example.com.  IN  NS  120  ns1.otherprovider.net.
        % 1  france.example.com.  IN  NS  120  ns2.otherprovider.net.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='server1.example.com.', qtype=A

        {cname_to_referral, #{
            question => {"server1.example.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = false,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"server1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{
                            dname = <<"server1.france.example.com">>
                        }}
                ],
                authority => [
                    {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns1.otherprovider.net">>
                    }},
                    {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns2.otherprovider.net">>
                    }}
                ],
                additional => []
            }
        }},

        % 0  unauth.example.com.  IN  CNAME  120  no-idea.example.org.
        % 1  .  IN  NS  518400  a.root-servers.net.
        % 1  .  IN  NS  518400  b.root-servers.net.
        % 1  .  IN  NS  518400  c.root-servers.net.
        % 1  .  IN  NS  518400  d.root-servers.net.
        % 1  .  IN  NS  518400  e.root-servers.net.
        % 1  .  IN  NS  518400  f.root-servers.net.
        % 1  .  IN  NS  518400  g.root-servers.net.
        % 1  .  IN  NS  518400  h.root-servers.net.
        % 1  .  IN  NS  518400  i.root-servers.net.
        % 1  .  IN  NS  518400  j.root-servers.net.
        % 1  .  IN  NS  518400  k.root-servers.net.
        % 1  .  IN  NS  518400  l.root-servers.net.
        % 1  .  IN  NS  518400  m.root-servers.net.
        % 2  .  IN  OPT  32768
        % 2  a.root-servers.net.  IN  A  3600000  198.41.0.4
        % 2  b.root-servers.net.  IN  A  3600000  192.228.79.201
        % 2  c.root-servers.net.  IN  A  3600000  192.33.4.12
        % 2  d.root-servers.net.  IN  A  3600000  128.8.10.90
        % 2  e.root-servers.net.  IN  A  3600000  192.203.230.10
        % 2  f.root-servers.net.  IN  A  3600000  192.5.5.241
        % 2  g.root-servers.net.  IN  A  3600000  192.112.36.4
        % 2  h.root-servers.net.  IN  A  3600000  128.63.2.53
        % 2  i.root-servers.net.  IN  A  3600000  192.36.148.17
        % 2  j.root-servers.net.  IN  A  3600000  192.58.128.30
        % 2  k.root-servers.net.  IN  A  3600000  193.0.14.129
        % 2  l.root-servers.net.  IN  A  3600000  198.32.64.12
        % 2  m.root-servers.net.  IN  A  3600000  202.12.27.33
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='unauth.example.com.', qtype=ANY

        {cname_to_unauth_any, #{
            question => {"unauth.example.com", ?DNS_TYPE_ANY},
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
                    {<<"unauth.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"no-idea.example.org">>}}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  unauth.example.com.  IN  CNAME  120  no-idea.example.org.
        % 1  .  IN  NS  518400  a.root-servers.net.
        % 1  .  IN  NS  518400  b.root-servers.net.
        % 1  .  IN  NS  518400  c.root-servers.net.
        % 1  .  IN  NS  518400  d.root-servers.net.
        % 1  .  IN  NS  518400  e.root-servers.net.
        % 1  .  IN  NS  518400  f.root-servers.net.
        % 1  .  IN  NS  518400  g.root-servers.net.
        % 1  .  IN  NS  518400  h.root-servers.net.
        % 1  .  IN  NS  518400  i.root-servers.net.
        % 1  .  IN  NS  518400  j.root-servers.net.
        % 1  .  IN  NS  518400  k.root-servers.net.
        % 1  .  IN  NS  518400  l.root-servers.net.
        % 1  .  IN  NS  518400  m.root-servers.net.
        % 2  .  IN  OPT  32768
        % 2  a.root-servers.net.  IN  A  3600000  198.41.0.4
        % 2  b.root-servers.net.  IN  A  3600000  192.228.79.201
        % 2  c.root-servers.net.  IN  A  3600000  192.33.4.12
        % 2  d.root-servers.net.  IN  A  3600000  128.8.10.90
        % 2  e.root-servers.net.  IN  A  3600000  192.203.230.10
        % 2  f.root-servers.net.  IN  A  3600000  192.5.5.241
        % 2  g.root-servers.net.  IN  A  3600000  192.112.36.4
        % 2  h.root-servers.net.  IN  A  3600000  128.63.2.53
        % 2  i.root-servers.net.  IN  A  3600000  192.36.148.17
        % 2  j.root-servers.net.  IN  A  3600000  192.58.128.30
        % 2  k.root-servers.net.  IN  A  3600000  193.0.14.129
        % 2  l.root-servers.net.  IN  A  3600000  198.32.64.12
        % 2  m.root-servers.net.  IN  A  3600000  202.12.27.33
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='unauth.example.com.', qtype=A

        {cname_to_unauth, #{
            question => {"unauth.example.com", ?DNS_TYPE_A},
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
                    {<<"unauth.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"no-idea.example.org">>}}
                ],
                authority => [],
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
            question => {"start.example.com", ?DNS_TYPE_A},
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
            question => {"semi-external.example.com", ?DNS_TYPE_A},
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

        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='example.com.', qtype=DNSKEY

        {direct_dnskey, #{
            question => {"example.com", ?DNS_TYPE_DNSKEY},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % 0  www.something.wtest.com.  IN  A  3600  4.3.2.1
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.something.wtest.com.', qtype=A

        {direct_wildcard, #{
            question => {"www.something.wtest.com", ?DNS_TYPE_A},
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

        % 0  _double._tcp.dc.test.com.  IN  SRV  3600  0 100 389 server1.test.com.
        % 0  _double._tcp.dc.test.com.  IN  SRV  3600  1 100 389 server1.test.com.
        % 2  server1.test.com.  IN  A  3600  1.2.3.4
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='_double._tcp.dc.test.com.', qtype=SRV

        {double_srv, #{
            question => {"_double._tcp.dc.test.com", ?DNS_TYPE_SRV},
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
                    {<<"_double._tcp.dc.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SRV, 3600,
                        #dns_rrdata_srv{
                            priority = 0, weight = 100, port = 389, target = <<"server1.test.com">>
                        }},
                    {<<"_double._tcp.dc.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SRV, 3600,
                        #dns_rrdata_srv{
                            priority = 1, weight = 100, port = 389, target = <<"server1.test.com">>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  double.example.com.  IN  A  120  192.168.5.1
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='double.example.com.', qtype=A

        {double, #{
            question => {"double.example.com", ?DNS_TYPE_A},
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
                    {<<"double.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 5, 1}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='example.com.', qtype=DS

        {ds_at_apex_noerror, #{
            question => {"example.com", ?DNS_TYPE_DS},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % 1  test.com.  IN  SOA  3600  ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='c.test.com.', qtype=ANY

        %{ent_any, {
        %question => {"c.test.com", ?DNS_TYPE_ANY},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %response => #{
        %answers => []},
        %authority => [
        %{<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.test.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
        %]},
        %additional => []
        %}}
        %}},

        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='sub.host.sub.example.com.', qtype=A

        % The record name is host.*.sub.example.com, however erldns only supports wildcards in the left-most position.

        %{ent_asterisk, {
        %question => {"sub.host.sub.example.com", ?DNS_TYPE_A},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %response => #{
        %answers => []},
        %authority => [
        %{<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{mname = <<"ns1.example.com">>, rname = <<"ahu.example.com">>, serial=2000081501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
        %]},
        %additional => []
        %}}
        %}},

        % TODO: ent_axfr

        % 1  test.com.  IN  SOA  3600  ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='b.c.test.com.', qtype=TXT

        {ent_rr_enclosed_in_ent, #{
            question => {"b.c.test.com", ?DNS_TYPE_TXT},
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

        % 1  test.com.  IN  SOA  3600  ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='c.test.com.', qtype=SOA

        %{ent_soa, {
        %question => {"c.test.com", ?DNS_TYPE_SOA},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %response => #{
        %answers => []},
        %authority => [
        %{<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.test.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
        %]},
        %additional => []
        %}}
        %}},

        % 0  something.a.b.c.test.com.  IN  A  3600  8.7.6.5
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='something.a.b.c.test.com.', qtype=A

        {ent_wildcard_below_ent, #{
            question => {"something.a.b.c.test.com", ?DNS_TYPE_A},
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
        }},

        % 1  test.com.  IN  SOA  3600  ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='c.test.com.', qtype=A

        %{ent, {
        %question => {"c.test.com", ?DNS_TYPE_A},
        %header => #dns_message{rc=?DNS_RCODE_NOERROR, rd=false, qr=true, tc=false, aa=true, oc=?DNS_OPCODE_QUERY}},
        %response => #{
        %answers => []},
        %authority => [
        %{<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 3600, #dns_rrdata_soa{mname = <<"ns1.test.com">>, rname = <<"ahu.example.com">>, serial=2005092501, refresh=28800, retry=7200, expire=604800, minimum = 86400}}
        %]},
        %additional => []
        %}}
        %}},

        % 4 TXT response with 0 to 3 backslashes before a semicolon.

        % 0  text0.example.com.  IN  TXT  120  "k=rsa; p=one"
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='text0.example.com.', qtype=TXT

        {escaped_txt_1, #{
            question => {"text0.example.com", ?DNS_TYPE_TXT},
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
                    {<<"text0.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_TXT, 120, #dns_rrdata_txt{
                        txt = [<<"k=rsa; p=one">>]
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % A series of CNAME pointers can lead to an outside reference, which should be
        % passed in the Answer section. PowerDNS sends an unauthoritative NOERROR,
        % bind sends a SERVFAIL.

        % 0  external.example.com.  IN  CNAME  120  somewhere.else.net.
        % 1  .  IN  NS  518400  a.root-servers.net.
        % 1  .  IN  NS  518400  b.root-servers.net.
        % 1  .  IN  NS  518400  c.root-servers.net.
        % 1  .  IN  NS  518400  d.root-servers.net.
        % 1  .  IN  NS  518400  e.root-servers.net.
        % 1  .  IN  NS  518400  f.root-servers.net.
        % 1  .  IN  NS  518400  g.root-servers.net.
        % 1  .  IN  NS  518400  h.root-servers.net.
        % 1  .  IN  NS  518400  i.root-servers.net.
        % 1  .  IN  NS  518400  j.root-servers.net.
        % 1  .  IN  NS  518400  k.root-servers.net.
        % 1  .  IN  NS  518400  l.root-servers.net.
        % 1  .  IN  NS  518400  m.root-servers.net.
        % 2  a.root-servers.net.  IN  A  3600000  198.41.0.4
        % 2  b.root-servers.net.  IN  A  3600000  192.228.79.201
        % 2  c.root-servers.net.  IN  A  3600000  192.33.4.12
        % 2  d.root-servers.net.  IN  A  3600000  128.8.10.90
        % 2  e.root-servers.net.  IN  A  3600000  192.203.230.10
        % 2  f.root-servers.net.  IN  A  3600000  192.5.5.241
        % 2  g.root-servers.net.  IN  A  3600000  192.112.36.4
        % 2  h.root-servers.net.  IN  A  3600000  128.63.2.53
        % 2  i.root-servers.net.  IN  A  3600000  192.36.148.17
        % 2  j.root-servers.net.  IN  A  3600000  192.58.128.30
        % 2  k.root-servers.net.  IN  A  3600000  193.0.14.129
        % 2  l.root-servers.net.  IN  A  3600000  198.32.64.12
        % 2  m.root-servers.net.  IN  A  3600000  202.12.27.33
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='external.example.com.', qtype=A

        {external_cname_pointer, #{
            question => {"external.example.com", ?DNS_TYPE_A},
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
                    {<<"external.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"somewhere.else.net">>}}
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
            question => {"www.a.b.c.d.e.something.wtest.com", ?DNS_TYPE_A},
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

        % 0  www.a.b.c.d.e.wtest.com.  IN  A  3600  6.7.8.9
        % 0  www.a.b.c.d.e.wtest.com.  IN  RRSIG  3600  A 8 7 3600 [expiry] [inception] [keytag] wtest.com. ...
        % 1  *.a.b.c.d.e.wtest.com.  IN  NSEC  86400  ns1.wtest.com. A RRSIG NSEC
        % 1  *.a.b.c.d.e.wtest.com.  IN  RRSIG  86400  NSEC 8 7 86400 [expiry] [inception] [keytag] wtest.com. ...
        % 2  .  IN  OPT  32768
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.a.b.c.d.e.wtest.com.', qtype=A

        {five_levels_wildcard, #{
            question => {"www.a.b.c.d.e.wtest.com", ?DNS_TYPE_A},
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
                    {<<"www.a.b.c.d.e.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{
                        ip = {6, 7, 8, 9}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % Verify that asking for A of a glue record returns a referral.

        % 1  usa.example.com.  IN  NS  120  usa-ns1.usa.example.com.
        % 1  usa.example.com.  IN  NS  120  usa-ns2.usa.example.com.
        % 2  usa-ns1.usa.example.com.  IN  A  120  192.168.4.1
        % 2  usa-ns2.usa.example.com.  IN  A  120  192.168.4.2
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='usa-ns2.usa.example.com.', qtype=A

        {glue_record, #{
            question => {"usa-ns2.usa.example.com", ?DNS_TYPE_A},
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
                    {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"usa-ns1.usa.example.com">>
                    }},
                    {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"usa-ns2.usa.example.com">>
                    }}
                ],
                additional => [
                    {<<"usa-ns1.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 4, 1}
                    }},
                    {<<"usa-ns2.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 4, 2}
                    }}
                ]
            }
        }},

        % When something.example.com is delegated to NS response that reside *within*
        % something.example.com, glue is needed. The IP addresses of the relevant NS
        % response should then be provided in the additional section.

        % 1  usa.example.com.  IN  NS  120  usa-ns1.usa.example.com.
        % 1  usa.example.com.  IN  NS  120  usa-ns2.usa.example.com.
        % 2  usa-ns1.usa.example.com.  IN  A  120  192.168.4.1
        % 2  usa-ns2.usa.example.com.  IN  A  120  192.168.4.2
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='www.usa.example.com.', qtype=A

        {glue_referral, #{
            question => {"www.usa.example.com", ?DNS_TYPE_A},
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
                    {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"usa-ns1.usa.example.com">>
                    }},
                    {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"usa-ns2.usa.example.com">>
                    }}
                ],
                additional => [
                    {<<"usa-ns1.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 4, 1}
                    }},
                    {<<"usa-ns2.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 4, 2}
                    }}
                ]
            }
        }},

        % 1  italy.example.com.  IN  NS  120  italy-ns1.example.com.
        % 1  italy.example.com.  IN  NS  120  italy-ns2.example.com.
        % 2  italy-ns1.example.com.  IN  A  120  192.168.5.1
        % 2  italy-ns2.example.com.  IN  A  120  192.168.5.2
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='www.italy.example.com.', qtype=A

        {internal_referral, #{
            question => {"www.italy.example.com", ?DNS_TYPE_A},
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
                    {<<"italy.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"italy-ns1.example.com">>
                    }},
                    {<<"italy.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"italy-ns2.example.com">>
                    }}
                ],
                additional => [
                    {<<"italy-ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 5, 1}
                    }},
                    {<<"italy-ns2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 5, 2}
                    }}
                ]
            }
        }},

        {internal_referral_glue, #{
            question => {"italy-ns1.example.com", ?DNS_TYPE_A},
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
                    {<<"italy-ns1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 5, 1}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 1  test.com.  IN  SOA  3600  ns1.test.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test.com.', qtype=TXT

        {long_name, #{
            question =>
                {
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
                    "test.com",
                    ?DNS_TYPE_TXT
                },
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

        % 0  start1.example.com.  IN  CNAME  120  start2.example.com.
        % 0  start2.example.com.  IN  CNAME  120  start3.example.com.
        % 0  start3.example.com.  IN  CNAME  120  start4.example.com.
        % 0  start4.example.com.  IN  A  120  192.168.2.2
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='start1.example.com.', qtype=A

        {multi_step_cname_resolution, #{
            question => {"start1.example.com", ?DNS_TYPE_A},
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
                    {<<"start1.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"start2.example.com">>}},
                    {<<"start2.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"start3.example.com">>}},
                    {<<"start3.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120,
                        #dns_rrdata_cname{dname = <<"start4.example.com">>}},
                    {<<"start4.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 2, 2}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  escapedtext.example.com.  IN  TXT  120  "begin" "the \"middle\" p\\art" "the end"
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='escapedtext.example.com.', qtype=TXT

        {multi_txt_escape_resolution, #{
            question => {"escapedtext.example.com", ?DNS_TYPE_TXT},
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
                    {<<"escapedtext.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_TXT, 120,
                        #dns_rrdata_txt{
                            txt = [<<"begin">>, <<"the \"middle\" p\\art">>, <<"the end">>]
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  multitext.example.com.  IN  TXT  120  "text part one" "text part two" "text part three"
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='multitext.example.com.', qtype=TXT

        {multi_txt_resolution, #{
            question => {"multitext.example.com", ?DNS_TYPE_TXT},
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
                    {<<"multitext.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_TXT, 120,
                        #dns_rrdata_txt{
                            txt = [<<"text part one">>, <<"text part two">>, <<"text part three">>]
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % Example.com has two MX response, one of which is out-of-bailiwick and should
        % not receive additional processing. The other is internal to the zone and has
        % three A response, which should all be in the additional section. For
        % additional difficulty, the question contains an odd CaSe.

        % 0  exAmplE.com.  IN  MX  120  10 smtp-servers.exAmplE.com.
        % 0  exAmplE.com.  IN  MX  120  15 smtp-servers.test.com.
        % 2  smtp-servers.exAmplE.com.  IN  A  120  192.168.0.2
        % 2  smtp-servers.exAmplE.com.  IN  A  120  192.168.0.3
        % 2  smtp-servers.exAmplE.com.  IN  A  120  192.168.0.4
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='exAmplE.com.', qtype=MX

        {mx_case_sensitivity_with_ap, #{
            question => {"exAmplE.com", ?DNS_TYPE_MX},
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
                    {<<"exAmplE.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120, #dns_rrdata_mx{
                        exchange = <<"smtp-servers.exAmplE.com">>, preference = 10
                    }},
                    {<<"exAmplE.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120, #dns_rrdata_mx{
                        exchange = <<"smtp-servers.test.com">>, preference = 15
                    }}
                ],
                authority => [],
                additional => [
                    {<<"smtp-servers.exAmplE.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                            ip = {192, 168, 0, 2}
                        }},
                    {<<"smtp-servers.exAmplE.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                            ip = {192, 168, 0, 3}
                        }},
                    {<<"smtp-servers.exAmplE.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 0, 4}
                    }}
                ]
            }
        }},

        % MX response cannot point to CNAMEs, according to the RFC. Yet when this
        % happens, a nameserver should not fall over, but let the mailserver process
        % the CNAME further (all do, even qmail).

        % 0  mail.example.com.  IN  MX  120  25 smtp1.example.com.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='mail.example.com.', qtype=MX

        {mx_to_cname, #{
            question => {"mail.example.com", ?DNS_TYPE_MX},
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
                    {<<"mail.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120, #dns_rrdata_mx{
                        exchange = <<"smtp1.example.com">>, preference = 25
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  example.com.  IN  MX  120  10 smtp-servers.example.com.
        % 0  example.com.  IN  MX  120  15 smtp-servers.test.com.
        % 2  smtp-servers.example.com.  IN  A  120  192.168.0.2
        % 2  smtp-servers.example.com.  IN  A  120  192.168.0.3
        % 2  smtp-servers.example.com.  IN  A  120  192.168.0.4
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='example.com.', qtype=MX

        {mx_with_simple_additional_processing, #{
            question => {"example.com", ?DNS_TYPE_MX},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120, #dns_rrdata_mx{
                        exchange = <<"smtp-servers.example.com">>, preference = 10
                    }},
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120, #dns_rrdata_mx{
                        exchange = <<"smtp-servers.test.com">>, preference = 15
                    }}
                ],
                authority => [],
                additional => [
                    {<<"smtp-servers.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                            ip = {192, 168, 0, 2}
                        }},
                    {<<"smtp-servers.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                            ip = {192, 168, 0, 3}
                        }},
                    {<<"smtp-servers.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 0, 4}
                    }}
                ]
            }
        }},

        % 0  enum.test.com.  IN  NAPTR  3600  100 50 "u" "e2u+sip" "" testuser.domain.com.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='enum.test.com.', qtype=NAPTR

        {naptr, #{
            question => {"enum.test.com", ?DNS_TYPE_NAPTR},
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
                    {<<"enum.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NAPTR, 3600, #dns_rrdata_naptr{
                        order = 100,
                        preference = 50,
                        flags = <<"u">>,
                        services = <<"e2u+sip">>,
                        regexp = <<>>,
                        replacement = <<"server1.test.com">>
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='ns2.example.com.', qtype=AAAA

        {non_existing_record_other_types_exist_ns, #{
            question => {"ns2.example.com", ?DNS_TYPE_AAAA},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='outpost.example.com.', qtype=AAAA

        {non_existing_record_other_types_exist, #{
            question => {"outpost.example.com", ?DNS_TYPE_AAAA},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % Verify that asking for NS at a delegation point returns a referral.

        % 1  usa.example.com.  IN  NS  120  usa-ns1.usa.example.com.
        % 1  usa.example.com.  IN  NS  120  usa-ns2.usa.example.com.
        % 2  usa-ns1.usa.example.com.  IN  A  120  192.168.4.1
        % 2  usa-ns2.usa.example.com.  IN  A  120  192.168.4.2
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='usa.example.com.', qtype=NS

        {ns_at_delegation, #{
            question => {"usa.example.com", ?DNS_TYPE_NS},
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
                    {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"usa-ns1.usa.example.com">>
                    }},
                    {<<"usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"usa-ns2.usa.example.com">>
                    }}
                ],
                additional => [
                    {<<"usa-ns1.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 4, 1}
                    }},
                    {<<"usa-ns2.usa.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 4, 2}
                    }}
                ]
            }
        }},

        % 1  blah.test.com.  IN  NS  3600  blah.test.com.
        % 2  blah.test.com.  IN  A  3600  192.168.6.1
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='blah.test.com.', qtype=MX

        {ns_with_identical_glue, #{
            question => {"blah.test.com", ?DNS_TYPE_MX},
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
                    {<<"blah.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"blah.test.com">>
                    }}
                ],
                additional => [
                    {<<"blah.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{
                        ip = {192, 168, 6, 1}
                    }}
                ]
            }
        }},

        % 1  example.com.  IN  SOA  86400  ns1.example.com. ahu.example.com. 2000081501 28800 7200 604800 86400
        % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='no-such-host.example.com.', qtype=A

        {nx_domain_for_unknown_record, #{
            question => {"no-such-host.example.com", ?DNS_TYPE_A},
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
                    {<<"example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SOA, 86400, #dns_rrdata_soa{
                        mname = <<"ns1.example.com">>,
                        rname = <<"ahu.example.com">>,
                        serial = 2000081501,
                        refresh = 28800,
                        retry = 7200,
                        expire = 604800,
                        minimum = 86400
                    }}
                ],
                additional => []
            }
        }},

        % If there is a more-specific subtree that matches part of a name,
        % a less-specific wildcard cannot match it.

        % 1  wtest.com.  IN  SOA  3600  ns1.wtest.com. ahu.example.com. 2005092501 28800 7200 604800 86400
        % Rcode: 3, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.a.something.wtest.com.', qtype=A

        {obscured_wildcard, #{
            question => {"www.a.something.wtest.com", ?DNS_TYPE_A},
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

        % 0  outpost.example.com.  IN  A  120  192.168.2.1
        % 0  www.example.com.  IN  CNAME  120  outpost.example.com.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='www.example.com.', qtype=A

        {one_step_cname_resolution, #{
            question => {"www.example.com", ?DNS_TYPE_A},
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
                    {<<"www.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 120, #dns_rrdata_cname{
                        dname = <<"outpost.example.com">>
                    }},
                    {<<"outpost.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{
                        ip = {192, 168, 2, 1}
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 1  france.example.com.  IN  NS  120  ns1.otherprovider.net.
        % 1  france.example.com.  IN  NS  120  ns2.otherprovider.net.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='www.france.example.com.', qtype=A

        {out_of_baliwick_referral, #{
            question => {"www.france.example.com", ?DNS_TYPE_A},
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
                    {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns1.otherprovider.net">>
                    }},
                    {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns2.otherprovider.net">>
                    }}
                ],
                additional => []
            }
        }},

        % DNS employs label compression to fit big answers in a small packet. This
        % test performs a query that without proper compression would not fit.

        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.1
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.10
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.11
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.12
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.13
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.14
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.15
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.16
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.17
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.18
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.19
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.2
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.20
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.21
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.22
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.23
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.24
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.25
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.3
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.4
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.5
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.6
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.7
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.8
        % 0  toomuchinfo-a.example.com.  IN  A  120  192.168.99.9
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='toomuchinfo-a.example.com.', qtype=A

        {pretty_big_packet, #{
            question => {"toomuchinfo-a.example.com", ?DNS_TYPE_A},
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
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 1}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 2}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 3}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 4}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 5}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 6}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 7}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 8}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 9}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 10}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 11}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 12}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 13}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 14}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 15}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 16}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 17}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 18}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 19}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 20}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 21}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 22}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 23}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 24}}},
                    {<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 25}}}
                ],
                authority => [],
                additional => []
            }
        }},

        % This test makes sure an CNAME record pointing at the root works

        % 0  toroot.test.com.  IN  CNAME  3600  .
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='toroot.test.com.', qtype=CNAME

        {root_cname, #{
            question => {"toroot.test.com", ?DNS_TYPE_CNAME},
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
                    {<<"toroot.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_CNAME, 3600, #dns_rrdata_cname{
                        dname = <<"test.com">>
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % This test makes sure an MX record pointing at the root works

        % 0  test.com.  IN  MX  3600  10 .
        % 0  test.com.  IN  MX  3600  15 smtp-servers.test.com.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='test.com.', qtype=MX

        {root_mx, #{
            question => {"test.com", ?DNS_TYPE_MX},
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
                    {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 3600, #dns_rrdata_mx{
                        exchange = <<"test.com">>, preference = 10
                    }},
                    {<<"test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 3600, #dns_rrdata_mx{
                        exchange = <<"smtp-servers.test.com">>, preference = 15
                    }}
                ],
                authority => [],
                additional => []
            }
        }},

        % This test makes sure an NS record pointing at the root works

        % 0  wtest.com.  IN  NS  3600  .
        % 0  wtest.com.  IN  NS  3600  ns1.wtest.com.
        % 2  ns1.wtest.com.  IN  A  3600  2.3.4.5
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='wtest.com.', qtype=NS

        {root_ns, #{
            question => {"wtest.com", ?DNS_TYPE_NS},
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
                    {<<"wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns1.wtest.com">>
                    }},
                    {<<"wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 3600, #dns_rrdata_ns{
                        dname = <<"ns2.wtest.com">>
                    }}
                ],
                authority => [],
                additional => [
                    {<<"ns1.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{
                        ip = {2, 3, 4, 5}
                    }},
                    {<<"ns2.wtest.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 3600, #dns_rrdata_a{
                        ip = {5, 6, 7, 8}
                    }}
                ]
            }
        }},

        % This test makes sure an SRV record pointing at the root works

        % 0  _root._tcp.dc.test.com.  IN  SRV  3600  0 0 0 .
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='_root._tcp.dc.test.com.', qtype=SRV

        {root_srv, #{
            question => {"_root._tcp.dc.test.com", ?DNS_TYPE_SRV},
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
                    {<<"_root._tcp.dc.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_SRV, 3600,
                        #dns_rrdata_srv{
                            priority = 0, weight = 0, port = 0, target = <<"">>
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 0  server1.test.com.  IN  RP  3600  ahu.ds9a.nl. counter.test.com.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='server1.test.com.', qtype=RP

        % NOTE: The RP record in not supported by erldns at the moment.
        % {rp, #{
        %     question => {"server1.test.com", ?DNS_TYPE_RP},
        %     response => #{
        %         header => #dns_message{
        %             rc = ?DNS_RCODE_NOERROR,
        %             rd = false,
        %             qr = true,
        %             tc = false,
        %             aa = true,
        %             oc = ?DNS_OPCODE_QUERY
        %         },
        %         answers => [
        %             {<<"server1.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_RP, 3600, #dns_rrdata_rp{
        %                 mbox = <<"ahu.ds9a.nl">>, txt = <<"counter.test.com">>
        %             }}
        %         ],
        %         authority => [],
        %         additional => []
        %     }
        % }},

        % A referral with the same name as the NS record itself, but now for a SOA
        % record.

        % 1  france.example.com.  IN  NS  120  ns1.otherprovider.net.
        % 1  france.example.com.  IN  NS  120  ns2.otherprovider.net.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='france.example.com.', qtype=SOA

        {same_level_referral_soa, #{
            question => {"france.example.com", ?DNS_TYPE_SOA},
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
                    {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns1.otherprovider.net">>
                    }},
                    {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns2.otherprovider.net">>
                    }}
                ],
                additional => []
            }
        }},

        % 1  france.example.com.  IN  NS  120  ns1.otherprovider.net.
        % 1  france.example.com.  IN  NS  120  ns2.otherprovider.net.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='france.example.com.', qtype=A

        {same_level_referral, #{
            question => {"france.example.com", ?DNS_TYPE_A},
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
                    {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns1.otherprovider.net">>
                    }},
                    {<<"france.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_NS, 120, #dns_rrdata_ns{
                        dname = <<"ns2.otherprovider.net">>
                    }}
                ],
                additional => []
            }
        }},

        % UDP dns packets can only be 512 bytes long - when they are longer, they need
        % to get truncated, and have the 'TC' bit set, to inform the client that they
        % need to requery over TCP. This query however does not need truncation, since
        % the information that causes things to go over limit is 'additional'.

        % 0  together-too-much.example.com.  IN  MX  120  25 toomuchinfo-a.example.com.
        % 0  together-too-much.example.com.  IN  MX  120  25 toomuchinfo-b.example.com.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % 2  toomuchinfo-X.example.com.  IN  A  120  192.168.99.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='together-too-much.example.com.', qtype=MX

        {too_big_for_udp_query_no_truncate_additional, #{
            question => {"together-too-much.example.com", ?DNS_TYPE_MX},
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
                    {<<"together-too-much.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120,
                        #dns_rrdata_mx{
                            exchange = <<"toomuchinfo-a.example.com">>, preference = 25
                        }},
                    {<<"together-too-much.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_MX, 120,
                        #dns_rrdata_mx{
                            exchange = <<"toomuchinfo-b.example.com">>, preference = 25
                        }}
                ],
                authority => [],
                additional => [
                    % In our case we just don't send any additionals if the packet is too large,
                    % since it is a performance enhancement only.
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,1}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,2}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,3}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,4}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,5}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,6}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,7}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,8}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,9}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,10}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,11}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,12}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,13}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,14}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,15}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,16}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,17}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,18}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,19}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,20}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,21}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,22}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,23}}},
                    %{<<"toomuchinfo-a.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120, #dns_rrdata_a{ip = {192,168,99,24}}}
                ]
            }
        }},

        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % 0  toomuchinfo-b.example.com.  IN  A  120  192.168.99.
        % Rcode: 0, RD: 0, QR: 1, TC: 1, AA: 1, opcode: 0
        % Reply to question for qname='toomuchinfo-b.example.com.', qtype=A

        {too_big_for_udp_query, #{
            question => {"toomuchinfo-b.example.com", ?DNS_TYPE_A},
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_NOERROR,
                    rd = false,
                    qr = true,
                    tc = true,
                    aa = true,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 26}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 27}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 28}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 29}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 30}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 31}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 32}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 33}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 34}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 35}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 36}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 37}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 38}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 39}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 40}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 41}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 42}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 43}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 44}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 45}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 46}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 47}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 48}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 49}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 50}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 51}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 52}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 53}}},
                    {<<"toomuchinfo-b.example.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_A, 120,
                        #dns_rrdata_a{ip = {192, 168, 99, 54}}}
                ],
                authority => [],
                additional => []
            }
        }},

        % When asked for a domain for which a nameserver is not authoritative, it
        % should return with an empty no-error packet, and drop the AA bit

        % 1  .  IN  NS  518400  a.root-servers.net.
        % 1  .  IN  NS  518400  b.root-servers.net.
        % 1  .  IN  NS  518400  c.root-servers.net.
        % 1  .  IN  NS  518400  d.root-servers.net.
        % 1  .  IN  NS  518400  e.root-servers.net.
        % 1  .  IN  NS  518400  f.root-servers.net.
        % 1  .  IN  NS  518400  g.root-servers.net.
        % 1  .  IN  NS  518400  h.root-servers.net.
        % 1  .  IN  NS  518400  i.root-servers.net.
        % 1  .  IN  NS  518400  j.root-servers.net.
        % 1  .  IN  NS  518400  k.root-servers.net.
        % 1  .  IN  NS  518400  l.root-servers.net.
        % 1  .  IN  NS  518400  m.root-servers.net.
        % 2  a.root-servers.net.  IN  A  3600000  198.41.0.4
        % 2  b.root-servers.net.  IN  A  3600000  192.228.79.201
        % 2  c.root-servers.net.  IN  A  3600000  192.33.4.12
        % 2  d.root-servers.net.  IN  A  3600000  128.8.10.90
        % 2  e.root-servers.net.  IN  A  3600000  192.203.230.10
        % 2  f.root-servers.net.  IN  A  3600000  192.5.5.241
        % 2  g.root-servers.net.  IN  A  3600000  192.112.36.4
        % 2  h.root-servers.net.  IN  A  3600000  128.63.2.53
        % 2  i.root-servers.net.  IN  A  3600000  192.36.148.17
        % 2  j.root-servers.net.  IN  A  3600000  192.58.128.30
        % 2  k.root-servers.net.  IN  A  3600000  193.0.14.129
        % 2  l.root-servers.net.  IN  A  3600000  198.32.64.12
        % 2  m.root-servers.net.  IN  A  3600000  202.12.27.33
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='this.domain.is.not.in.powerdns.', qtype=A

        {unknown_domain, #{
            question => {"this.domain.is.not.in.the.server", ?DNS_TYPE_A},
            ignore => [authority, additional],
            response => #{
                header => #dns_message{
                    rc = ?DNS_RCODE_REFUSED,
                    rd = false,
                    qr = true,
                    tc = false,
                    aa = false,
                    oc = ?DNS_OPCODE_QUERY
                },
                answers => [],
                authority => [],
                additional => []
            }
        }},

        % This test tries to resolve a TXT record that is directly available in
        % the database, but is longer than 255 characters. This requires splitting.

        % 0  very-long-txt.test.com.  IN  TXT  3600  "A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you" " won't believe how long!"
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
        % Reply to question for qname='very-long-txt.test.com.', qtype=TXT

        {very_long_text, #{
            question => {"very-long-txt.test.com", ?DNS_TYPE_TXT},
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
                    {<<"very-long-txt.test.com">>, ?DNS_CLASS_IN, ?DNS_TYPE_TXT, 3600,
                        #dns_rrdata_txt{
                            txt = [
                                <<"A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you">>,
                                <<" won't believe how long!">>
                            ]
                        }}
                ],
                authority => [],
                additional => []
            }
        }},

        % 1  sub.test.test.com.  IN  NS  3600  ns-test.example.net.test.com.
        % Rcode: 0, RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0
        % Reply to question for qname='www.sub.test.test.com.', qtype=A

        {wildcard_overlaps_delegation, #{
            question => {"www.sub.test.test.com", ?DNS_TYPE_A},
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
            question => {"www.something.wtest.com", ?DNS_TYPE_TXT},
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
        }}
    ].

%hex_to_bin(Bin) when is_binary(Bin) ->
%Fun = fun(A, B) ->
%case io_lib:fread("~16u", [A, B]) of
%{ok, [V], []} -> V;
%_ -> error(badarg)
%end
%end,
%<< <<(Fun(A,B))>> || <<A, B>> <= Bin >>.
