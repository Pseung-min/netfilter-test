LDLIBS=-lnetfilter_queue

all: netfilter-test

netfilter-test: netfilter-test.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f netfilter-test *.o