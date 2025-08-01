LDLIBS += -lpcap

all: send-arp

main.o: main.cpp

arphdr.o: arphdr.h arphdr.cpp

ethhdr.o: ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

send-arp: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o