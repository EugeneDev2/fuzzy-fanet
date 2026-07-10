CC      ?= gcc
CFLAGS  ?= -std=c99 -Wall -Wextra -O2
LDLIBS  ?= -lm

SRC = src/fuzzy_fanet.c src/fanet_routing.c

.PHONY: all test sim clean

all: test_fuzzy sim_demo

# unit test for the fuzzy core
test_fuzzy: src/fuzzy_fanet.c test/test_fuzzy.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# full PC simulation: Standard vs Fuzzy AODV under Black Hole attack
sim_demo: $(SRC) sim/vnet.c sim/sim_main.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

test: test_fuzzy
	./test_fuzzy

sim: sim_demo
	./sim_demo

clean:
	rm -f test_fuzzy sim_demo *.o
