LOCAL = ../..
LIBSPATH = -L ${LOCAL}/libsockpp -Wl,-R$(LOCAL)/libsockpp '-Wl,-R$$ORIGIN' -L /usr/local/lib
INCS = -I /usr/local/include -I ${LOCAL}/
LIBS = -l sockpp

SRC_TEST0 = client_example.cpp
OBJ_TEST0 = ${SRC_TEST0:.cpp=.o}
SRC_TEST1 = chunked_example.cpp
OBJ_TEST1 = ${SRC_TEST1:.cpp=.o}
SRC_TEST2 = streaming_example.cpp
OBJ_TEST2 = ${SRC_TEST2:.cpp=.o}
SRC_TEST3 = requests_example.cpp
OBJ_TEST3 = ${SRC_TEST3:.cpp=.o}
SRC_TEST4 = multi_example.cpp
OBJ_TEST4 = ${SRC_TEST4:.cpp=.o}
SRC_TEST5 = multiasync_example.cpp
OBJ_TEST5 = ${SRC_TEST5:.cpp=.o}
SRC_TEST6 = sslclient_example.cpp
OBJ_TEST6 = ${SRC_TEST6:.cpp=.o}
SRC_TEST7 = sslserver_example.cpp
OBJ_TEST7 = ${SRC_TEST7:.cpp=.o}
SRC_TEST8 = sslstreaming_example.cpp
OBJ_TEST8 = ${SRC_TEST8:.cpp=.o}
SRC_TEST9 = sslmulti_example.cpp
OBJ_TEST9 = ${SRC_TEST9:.cpp=.o}
SRC_TESTA = sslmultiasync_example.cpp
OBJ_TESTA = ${SRC_TESTA:.cpp=.o}
SRC_TESTB = reuseclient_example.cpp
OBJ_TESTB = ${SRC_TESTB:.cpp=.o}

CC = c++
RELEASE_CFLAGS = -std=c++17 -c -Wall -fPIE -fPIC -pedantic -O3 ${INCS}
DEBUG_CFLAGS = -std=c++17 -c -Wall -fPIE -fPIC -pedantic -g ${INCS}
CFLAGS = ${RELEASE_CFLAGS}
LDFLAGS += ${LIBSPATH} ${LIBS}

all: client_example \
  chunked_example \
  streaming_example \
  requests_example \
  multi_example \
  multiasync_example \
  sslclient_example \
  sslserver_example \
  sslstreaming_example \
  sslmulti_example \
  sslmultiasync_example \
  reuseclient_example

.cpp.o:
	@echo CC $<
	@${CC} ${CFLAGS} $<

client_example: ${OBJ_TEST0}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST0} ${LDFLAGS}

chunked_example: ${OBJ_TEST1}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST1} ${LDFLAGS}

streaming_example: ${OBJ_TEST2}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST2} ${LDFLAGS}

requests_example: ${OBJ_TEST3}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST3} ${LDFLAGS}

multi_example: ${OBJ_TEST4}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST4} ${LDFLAGS}

multiasync_example: ${OBJ_TEST5}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST5} ${LDFLAGS}

sslclient_example: ${OBJ_TEST6}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST6} ${LDFLAGS}

sslserver_example: ${OBJ_TEST7}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST7} ${LDFLAGS}

sslstreaming_example: ${OBJ_TEST8}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST8} ${LDFLAGS}

sslmulti_example: ${OBJ_TEST9}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST9} ${LDFLAGS}

sslmultiasync_example: ${OBJ_TESTA}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TESTA} ${LDFLAGS}

reuseclient_example: ${OBJ_TESTB}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TESTB} ${LDFLAGS}

clean:
	@echo Cleaning
	@rm -f ${OBJ_TEST0} \
    ${OBJ_TEST1} \
    ${OBJ_TEST2} \
    ${OBJ_TEST3} \
    ${OBJ_TEST4} \
    ${OBJ_TEST5} \
    ${OBJ_TEST6} \
    ${OBJ_TEST7} \
    ${OBJ_TEST8} \
    ${OBJ_TEST9} \
    ${OBJ_TESTA} \
    ${OBJ_TESTB}
	@rm -f *example
