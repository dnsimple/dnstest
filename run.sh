#!/bin/sh

erl -config dnstest.config -pa ebin deps/**/ebin -s dnstest -- $*

