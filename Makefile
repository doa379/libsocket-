LOCAL = ..
LIBSPATH = -L ${LOCAL}/libsockpp -Wl,-R$(LOCAL)/libsockpp '-Wl,-R$$ORIGIN' -L /usr/local/lib
INCS = -I /usr/local/include -I ${LOCAL}/
LIBS = -l ssl -l crypto

SRC_LIBSOCK = sock.cpp utils.cpp
OBJ_LIBSOCK = ${SRC_LIBSOCK:.cpp=.o}

REL_CFLAGS = -O3
DBG_CFLAGS = -g
REL_LDFLAGS = -s
DBG_LDFLAGS =

CFLAGS = -std=c++17 -c -Wall -fPIE -fPIC -pedantic ${DBG_CFLAGS} ${INCS}
LDFLAGS = ${DBG_LDFLAGS} ${LIBSPATH}
CC = c++

all: libsockpp.so

.cpp.o:
	@echo CC $<
	@${CC} ${CFLAGS} $<

libsockpp.so: ${OBJ_LIBSOCK}
	@echo CC -o $@
	@${CC} -shared -o $@ ${OBJ_LIBSOCK} ${LDFLAGS} ${LIBS}

clean:
	@echo Cleaning
	@rm -f ${OBJ_LIBSOCK}
	@rm -f libsockpp.so
