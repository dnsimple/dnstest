REBAR:=$(shell which rebar3 || echo ./rebar3)
REBAR_URL:="https://s3.amazonaws.com/rebar3/rebar3"

all: clean build

$(REBAR):
	wget $(REBAR_URL) && chmod +x rebar3

build: $(REBAR)
	$(REBAR) compile

fresh: $(REBAR)
	rm -Rf _build

clean: $(REBAR)
	$(REBAR) clean

test: $(REBAR)
	$(REBAR) fmt --check
	$(REBAR) eunit skip_deps=true

format: $(REBAR)
	$(REBAR) fmt
