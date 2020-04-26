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

packet_gen:	packet_gen3.o
	$(CC) -pthread -D$(LOCKING_MECHANISM) packet_gen3.c -o packet_gen

udp_gen:	packet_gen3.o
	$(CC) -pthread -D$(LOCKING_MECHANISM) packet_gen3.c -o udp_gen

all:	packet_gen	udp_gen

clean:
	@echo "removing packet_gen"
	rm -rf a.out *.o packet_gen udp_gen 
