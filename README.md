# DNS Test Suite

Regression tests taken from the PowerDNS 3 regression test suite and converted to an Erlang environment.

## Building

```bash
make
```

## Configuration

You can find the configuration in [`dnstest.config`](./dnstest.config). Modify it at will to point it to the DNS server you wish to test against.

## Running

You'll need to have a DNS server running. For example, start [`erldns`](https://github.com/dnsimple/erldns) before running this testing tool.

### The Entire Suite

```bash
run.sh
```

### A Single Test

When the shell script runs, you will be left with a console. From there you may run individual tests with `dnstest:run(atom)` where `atom` is the atom identifier of the test.

## Testing `dnstest` Itself

```bash
make test
```
