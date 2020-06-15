# DNS Test Suite

Regression tests taken from the PowerDNS 3 regression test suite and converted to an Erlang environment.

## Running

### The entire suite


```bash
run.sh
```

### A Single test

When the shell script runs you will be left with a console. From there you may run individual tests with `dnstest:run(atom)` where `atom` is the atom identifier of the test.
