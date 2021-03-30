LOCAL = ../
LIBS_PATH = -L /usr/lib64 -L /usr/local/lib -L ${LOCAL}/libsocket++
INCS = -I /usr/local/include -I ${LOCAL}
LIBS = -l ssl -l crypto

SRC_LIBSOCKET = socket.cpp
OBJ_LIBSOCKET = ${SRC_LIBSOCKET:.cpp=.o}

SRC_TEST0 = client_example.cpp
OBJ_TEST0 = ${SRC_TEST0:.cpp=.o}
SRC_TEST1 = server_example.cpp
OBJ_TEST1 = ${SRC_TEST1:.cpp=.o}

CC = c++
CFLAGS = -std=c++14 -c -Wall -Werror -fPIE -fPIC -pedantic -O3 ${INCS} -g
LDFLAGS = ${LIBS_PATH} ${LIBS} -Wl,-rpath,$(CURDIR)

all: libsocket++.so client_example server_example

.cpp.o:
		@echo CC $<
		@${CC} ${CFLAGS} $<

libsocket++.so: ${OBJ_LIBSOCKET}
		@echo CC -o $@
		@${CC} -shared -o $@ ${OBJ_LIBSOCKET} ${LDFLAGS}

client_example: ${OBJ_TEST0}
		@echo CC -o $@
		@${CC} -o $@ ${OBJ_TEST0} ${LDFLAGS} -l socket++ -l pthread

server_example: ${OBJ_TEST1}
		@echo CC -o $@
		@${CC} -o $@ ${OBJ_TEST1} ${LDFLAGS} -l socket++

clean:
		@echo Cleaning
		@rm -f ${OBJ_LIBSOCKET} ${OBJ_TEST0} ${OBJ_TEST1}
		@rm -f *example
