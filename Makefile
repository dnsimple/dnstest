all: clean build

build:
	rebar3 compile

fresh:
	rm -Rf _build

clean:
	rebar3 clean

test:
	rebar3 fmt --check
	rebar3 lint
	rebar3 xref
	rebar3 dialyzer
	rebar3 ex_doc
	rebar3 eunit skip_deps=true

format:
	rebar3 fmt
