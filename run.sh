#!/bin/sh

rebar3 compile
erl -config dnstest.config -pa _build/default/lib/**/ebin -s dnstest -- $*
