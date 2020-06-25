IDIR=/usr/local/lib
CC=gcc
CFLAGS=-I${IDIR} -lsodium

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: ${OBJS} main elgamal_test
	echo "All made."

main:
	${CC} -o $@ $@.o ${CFLAGS}

elgamal_test:
	${CC} -o $@ $@.o ${CFLAGS} -lcunit

%.o: %.c
	${CC} ${CFLAGS} -c -o $@ $<

clean:
	rm -f ${OBJS} main elgamal_test
	@echo "All cleaned up!"
