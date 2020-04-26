LOCKING_MECHANISM ?= USE_PTHREAD_COMMON_MUTEX

#CC ?= gcc
ifdef CC
$(info "CC already Defined to" $(CC))
endif

ifndef CC
$(info "CC NOT DEFINED")
CC=gcc
endif

#target:	prerequisites
#		recipie

packet_gen:	arp.o packet_gen3.o
	$(CC) -pthread -o packet_gen packet_gen3.o arp.o

packet_gen3.o:	packet_gen3.c arp.h
	$(CC) -D$(LOCKING_MECHANISM) -c packet_gen3.c

arp.o:	arp.c
	$(CC) -c arp.c -o arp.o

all:	packet_gen

clean:
	@echo "removing packet_gen"
	rm -rf a.out *.o packet_gen udp_gen
