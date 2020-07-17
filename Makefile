BIN=./bin/
IDIR=/usr/local/lib
CC=c99
CFLAGS=-I${IDIR} -lsodium -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wredundant-decls -Wshadow -Wsign-conversion -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused -DINFO_PRINT='1' 

OBJS = $(patsubst src/%.c, obj/%.o, $(wildcard src/*.c))

PROG=main keygen combine-keys encrypt_array decrypt_array combine-arrays
BIN_LIST=$(addprefix $(BIN), $(PROG))

#all: ${OBJS} $(BIN_LIST)
all: ${OBJS} ${BIN_LIST} tests/elgamal_test
	echo "All made."

${BIN_LIST}: bin/%: obj/%.o obj/elgamal.o
	${CC} -o $@ $^ ${CFLAGS}

tests/elgamal_test: obj/elgamal_test.o src/elgamal.h
	${CC} -o $@ $^ ${CFLAGS} -lcunit obj/elgamal.o 

obj/%.o: src/%.c  src/elgamal.h
	${CC} ${CFLAGS} -c -o $@ $<

check: all
	cd tests/; \
	./elgamal_test; \
	./command_line_test.sh;


clean:
	rm -rf obj/*.o ${BIN_LIST} tests/tmp* tests/elgamal_test
	cd tests/; ./command_line_cleanup.sh
	@echo "All cleaned up!"
