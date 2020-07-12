IDIR=/usr/local/lib
CC=gcc
CFLAGS=-I${IDIR} -lsodium

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: ${OBJS} main elgamal_test keygen-node
	echo "All made."

main:
	${CC} -o $@ $@.o ${CFLAGS}

elgamal_test:
	${CC} -o $@ $@.o ${CFLAGS} -lcunit

keygen-node:
	${CC} -o $@ $@.o ${CFLAGS}

%.o: %.c
	${CC} ${CFLAGS} -c -o $@ $<

clean:
	rm -f ${OBJS} main elgamal_test keygen-node
	@echo "All cleaned up!"
