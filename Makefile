LOCAL = ..
LIBSPATH = -L ${LOCAL}/libsockpp -Wl,-R$(LOCAL)/libsockpp '-Wl,-R$$ORIGIN' -L /usr/local/lib
INCS = -I /usr/local/include -I ${LOCAL}/
LIBS = -l ssl -l crypto

SRC_LIBSOCK = sock.cpp utils.cpp
OBJ_LIBSOCK = ${SRC_LIBSOCK:.cpp=.o}
SRC_TEST0 = client_example.cpp
OBJ_TEST0 = ${SRC_TEST0:.cpp=.o}
SRC_TEST1 = server_example.cpp
OBJ_TEST1 = ${SRC_TEST1:.cpp=.o}
SRC_TEST2 = sslclient_example.cpp
OBJ_TEST2 = ${SRC_TEST2:.cpp=.o}
SRC_TEST3 = sslserver_example.cpp
OBJ_TEST3 = ${SRC_TEST3:.cpp=.o}
SRC_TEST4 = multiclient_example.cpp
OBJ_TEST4 = ${SRC_TEST4:.cpp=.o}
SRC_TEST5 = multisslclient_example.cpp
OBJ_TEST5 = ${SRC_TEST5:.cpp=.o}
SRC_TEST6 = streaming_example.cpp
OBJ_TEST6 = ${SRC_TEST6:.cpp=.o}
SRC_TEST7 = sslstreaming_example.cpp
OBJ_TEST7 = ${SRC_TEST7:.cpp=.o}

CC = c++
RELEASE_CFLAGS = -std=c++17 -c -Wall -fPIE -fPIC -pedantic -O3 ${INCS}
DEBUG_CFLAGS = -std=c++17 -c -Wall -fPIE -fPIC -pedantic -g ${INCS}
CFLAGS = ${DEBUG_CFLAGS}
LDFLAGS += ${LIBSPATH}

all: libsockpp.so \
  client_example \
  server_example \
  sslclient_example \
  sslserver_example \
  multiclient_example \
  multisslclient_example \
  streaming_example \
  sslstreaming_example

.cpp.o:
	@echo CC $<
	@${CC} ${CFLAGS} $<

libsockpp.so: ${OBJ_LIBSOCK}
	@echo CC -o $@
	@${CC} -shared -o $@ ${OBJ_LIBSOCK} ${LDFLAGS} ${LIBS}

client_example: ${OBJ_TEST0}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST0} ${LDFLAGS} -l sockpp

server_example: ${OBJ_TEST1}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST1} ${LDFLAGS} -l sockpp

sslclient_example: ${OBJ_TEST2}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST2} ${LDFLAGS} -l sockpp

sslserver_example: ${OBJ_TEST3}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST3} ${LDFLAGS} -l sockpp

multiclient_example: ${OBJ_TEST4}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST4} ${LDFLAGS} -l sockpp

multisslclient_example: ${OBJ_TEST5}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST5} ${LDFLAGS} -l sockpp

streaming_example: ${OBJ_TEST6}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST6} ${LDFLAGS} -l sockpp

sslstreaming_example: ${OBJ_TEST7}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST7} ${LDFLAGS} -l sockpp

clean:
	@echo Cleaning
	@rm -f ${OBJ_LIBSOCK} \
    ${OBJ_TEST0} \
    ${OBJ_TEST1} \
    ${OBJ_TEST2} \
    ${OBJ_TEST3} \
    ${OBJ_TEST4} \
    ${OBJ_TEST5} \
    ${OBJ_TEST6} \
    ${OBJ_TEST7}
	@rm -f libsockpp.so *example
