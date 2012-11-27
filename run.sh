#!/bin/sh

erl -pa ebin deps/**/ebin -s dnstest -- $1

