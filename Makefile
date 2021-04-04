LOCAL = ../
LIBSPATH = -L ${LOCAL}/libsocket++ -Wl,-R$(LOCAL)/libsocket++ '-Wl,-R$$ORIGIN'
INCS = -I /usr/local/include -I ${LOCAL}
LIBS = -l ssl -l crypto

SRC_LIBSOCKET = socket.cpp
OBJ_LIBSOCKET = ${SRC_LIBSOCKET:.cpp=.o}

SRC_TEST0 = client_example.cpp
OBJ_TEST0 = ${SRC_TEST0:.cpp=.o}
SRC_TEST1 = server_example.cpp
OBJ_TEST1 = ${SRC_TEST1:.cpp=.o}
SRC_TEST2 = sslclient_example.cpp
OBJ_TEST2 = ${SRC_TEST2:.cpp=.o}
SRC_TEST3 = sslserver_example.cpp
OBJ_TEST3 = ${SRC_TEST3:.cpp=.o}

CC = c++
CFLAGS = -std=c++14 -c -Wall -Werror -fPIE -fPIC -pedantic -O3 ${INCS}
LDFLAGS += ${LIBSPATH}

all: libsocket++.so client_example server_example sslclient_example sslserver_example

.cpp.o:
		@echo CC $<
		@${CC} ${CFLAGS} $<

libsocket++.so: ${OBJ_LIBSOCKET}
		@echo CC -o $@
		@${CC} -shared -o $@ ${OBJ_LIBSOCKET} ${LDFLAGS} ${LIBS}

client_example: ${OBJ_TEST0}
		@echo CC -o $@
		@${CC} -o $@ ${OBJ_TEST0} ${LDFLAGS} -l socket++

server_example: ${OBJ_TEST1}
		@echo CC -o $@
		@${CC} -o $@ ${OBJ_TEST1} ${LDFLAGS} -l socket++

sslclient_example: ${OBJ_TEST2}
		@echo CC -o $@
		@${CC} -o $@ ${OBJ_TEST2} ${LDFLAGS} -l socket++

sslserver_example: ${OBJ_TEST3}
		@echo CC -o $@
		@${CC} -o $@ ${OBJ_TEST3} ${LDFLAGS} -l socket++

clean:
		@echo Cleaning
		@rm -f ${OBJ_LIBSOCKET} ${OBJ_TEST0} ${OBJ_TEST1} ${OBJ_TEST2} ${OBJ_TEST3}
		@rm -f *example
