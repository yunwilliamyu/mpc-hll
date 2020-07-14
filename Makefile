BIN=./bin/
IDIR=/usr/local/lib
CC=c99
CFLAGS=-I${IDIR} -lsodium -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wredundant-decls -Wshadow -Wsign-conversion -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused

OBJS = $(patsubst src/%.c, obj/%.o, $(wildcard src/*.c))

PROG=main keygen combine-keys
BIN_LIST=$(addprefix $(BIN), $(PROG))

#all: ${OBJS} $(BIN_LIST)
all: ${OBJS} ${BIN_LIST} tests/elgamal_test
	echo "All made."

${BIN_LIST}:
	${CC} -o $@ obj/$(@F).o ${CFLAGS} obj/elgamal.o

tests/elgamal_test:
	${CC} -o $@ obj/$(@F).o ${CFLAGS} -lcunit obj/elgamal.o

obj/%.o: src/%.c
	${CC} ${CFLAGS} -c -o $@ $<

clean:
	rm -rf obj/*.o bin/* tests/*
	@echo "All cleaned up!"
