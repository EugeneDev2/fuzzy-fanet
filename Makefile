CC      := gcc
CFLAGS  ?= -std=c99 -Wall -Wextra -O2
LDLIBS  ?= -lm

CORE = src/fuzzy_fanet.c src/fanet_trust.c src/fanet_routing.c

.PHONY: all test sim clean

all: test_fuzzy test_trust test_routing sim_demo

# unit test: the fuzzy controller
test_fuzzy: src/fuzzy_fanet.c test/test_fuzzy.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# unit test: the behavioural trust manager
test_trust: src/fanet_trust.c test/test_trust.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# edge-case test: routing-layer packet bounds
test_routing: $(CORE) test/test_routing.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# full PC simulation: Standard vs Fuzzy AODV under Black Hole attack
sim_demo: $(CORE) sim/vnet.c sim/sim_main.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

test: test_fuzzy test_trust test_routing
	./test_fuzzy
	@echo ""
	./test_trust
	@echo ""
	./test_routing

sim: sim_demo
	./sim_demo

clean:
	rm -f test_fuzzy test_trust test_routing sim_demo *.o *.exe
