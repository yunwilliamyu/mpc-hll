IDIR=/usr/local/lib
CC=gcc
CFLAGS=-I${IDIR} -lsodium

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: ${OBJS} main elgamal_test keygen-node keygen-central
	echo "All made."

main:
	${CC} -o $@ $@.o ${CFLAGS}

elgamal_test:
	${CC} -o $@ $@.o ${CFLAGS} -lcunit

keygen-node:
	${CC} -o $@ $@.o ${CFLAGS}

keygen-central:
	${CC} -o $@ $@.o ${CFLAGS}

%.o: %.c
	${CC} ${CFLAGS} -c -o $@ $<

clean:
	rm -f ${OBJS} main elgamal_test keygen-node keygen-central
	@echo "All cleaned up!"
