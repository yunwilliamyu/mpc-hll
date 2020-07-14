IDIR=/usr/local/lib
CC=c99
CFLAGS=-I${IDIR} -lsodium -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wredundant-decls -Wshadow -Wsign-conversion -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: ${OBJS} main elgamal_test keygen-node keygen-central
	echo "All made."

main:
	${CC} -o $@ $@.o ${CFLAGS} elgamal.o

elgamal_test:
	${CC} -o $@ $@.o ${CFLAGS} -lcunit elgamal.o

keygen-node:
	${CC} -o $@ $@.o ${CFLAGS} elgamal.o

keygen-central:
	${CC} -o $@ $@.o ${CFLAGS} elgamal.o

%.o: %.c
	${CC} ${CFLAGS} -c -o $@ $<

clean:
	rm -f ${OBJS} main elgamal_test keygen-node keygen-central
	@echo "All cleaned up!"
