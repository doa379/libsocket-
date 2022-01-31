LOCAL = ../..
LIBSPATH = -L ${LOCAL}/libsockpp -Wl,-R$(LOCAL)/libsockpp '-Wl,-R$$ORIGIN' -L /usr/local/lib
INCS = -I /usr/local/include -I ${LOCAL}/
LIBS = -l sockpp

SRC_TEST0 = client.cpp
OBJ_TEST0 = ${SRC_TEST0:.cpp=.o}
SRC_TEST1 = chunked.cpp
OBJ_TEST1 = ${SRC_TEST1:.cpp=.o}
SRC_TEST2 = streaming.cpp
OBJ_TEST2 = ${SRC_TEST2:.cpp=.o}
SRC_TEST3 = requests.cpp
OBJ_TEST3 = ${SRC_TEST3:.cpp=.o}
SRC_TEST4 = multi.cpp
OBJ_TEST4 = ${SRC_TEST4:.cpp=.o}
SRC_TEST6 = sslclient.cpp
OBJ_TEST6 = ${SRC_TEST6:.cpp=.o}
SRC_TEST7 = sslserver.cpp
OBJ_TEST7 = ${SRC_TEST7:.cpp=.o}
SRC_TEST8 = sslstreaming.cpp
OBJ_TEST8 = ${SRC_TEST8:.cpp=.o}
SRC_TEST9 = sslmulti.cpp
OBJ_TEST9 = ${SRC_TEST9:.cpp=.o}
SRC_TESTB = reuseclient.cpp
OBJ_TESTB = ${SRC_TESTB:.cpp=.o}

CC = c++
REL_CFLAGS = -std=c++17 -c -Wall -fPIE -fPIC -pedantic -O3 ${INCS}
DEB_CFLAGS = -std=c++17 -c -Wall -fPIE -fPIC -pedantic -g ${INCS}
CFLAGS = ${REL_CFLAGS}
LDFLAGS += ${LIBSPATH} ${LIBS}

all: client \
  chunked \
  streaming \
  requests \
  multi \
  sslclient \
  sslserver \
  sslstreaming \
  sslmulti \
  reuseclient

.cpp.o:
	@echo CC $<
	@${CC} ${CFLAGS} $<

client: ${OBJ_TEST0}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST0} ${LDFLAGS}

chunked: ${OBJ_TEST1}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST1} ${LDFLAGS}

streaming: ${OBJ_TEST2}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST2} ${LDFLAGS}

requests: ${OBJ_TEST3}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST3} ${LDFLAGS}

multi: ${OBJ_TEST4}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST4} ${LDFLAGS}

sslclient: ${OBJ_TEST6}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST6} ${LDFLAGS}

sslserver: ${OBJ_TEST7}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST7} ${LDFLAGS}

sslstreaming: ${OBJ_TEST8}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST8} ${LDFLAGS}

sslmulti: ${OBJ_TEST9}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TEST9} ${LDFLAGS}

reuseclient: ${OBJ_TESTB}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ_TESTB} ${LDFLAGS}

clean:
	@echo Cleaning
	@rm -f ${OBJ_TEST0} \
    ${OBJ_TEST1} \
    ${OBJ_TEST2} \
    ${OBJ_TEST3} \
    ${OBJ_TEST4} \
    ${OBJ_TEST6} \
    ${OBJ_TEST7} \
    ${OBJ_TEST8} \
    ${OBJ_TEST9} \
    ${OBJ_TESTB}
	@rm -f client \
	chunked \
	streaming \
  requests \
  multi \
  sslclient \
  sslserver \
  sslstreaming \
  sslmulti \
  reuseclient
