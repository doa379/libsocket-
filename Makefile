LOCAL = ..
LIBSPATH = -L ${LOCAL}/libsockpp -Wl,-R$(LOCAL)/libsockpp '-Wl,-R$$ORIGIN' -L /usr/local/lib
INCS = -I /usr/local/include -I ${LOCAL}/
LIBS = -l ssl -l crypto

SRC_LIBSOCK = sock.cpp utils.cpp
OBJ_LIBSOCK = ${SRC_LIBSOCK:.cpp=.o}

CC = c++
REL_CFLAGS = -std=c++17 -c -Wall -fPIE -fPIC -pedantic -O3 ${INCS}
DEB_CFLAGS = -std=c++17 -c -Wall -fPIE -fPIC -pedantic -g ${INCS}
CFLAGS = ${REL_CFLAGS}
LDFLAGS += ${LIBSPATH}

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
