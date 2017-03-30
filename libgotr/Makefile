# libgotr version
MAJOR = 0
MINOR = 2
VERSION = ${MAJOR}.${MINOR}

# system specific build configuration
include config.mk

LIBA = libgotr.a
LIBSO = libgotr.so.${VERSION}
SRC = messaging.c gotr.c util.c gka.c b64.c crypto.c key.c
INC = messaging.h gotr.h util.h gka.h b64.h crypto.h key.h user.h
OBJ = ${SRC:.c=.o}

# binary which generates a private key
GENKEY = gotr_genkey
GENKEY_SRC = genkey.c
GENKEY_INC = crypto.h
GENKEY_OBJ = ${GENKEY_SRC:.c=.o}

CLIENT = client
CLIENT_SRC = client.c
CLIENT_INC = gotr.h
CLIENT_OBJ = ${CLIENT_SRC:.c=.o}

TEST = test
TEST_SRC = test.c
TEST_INC = test.h
TEST_OBJ = ${TEST_SRC:.c=.o}

all: options ${LIBA} ${LIBSO} ${GENKEY} ${CLIENT}

options:
	@echo build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ}: ${INC} config.mk
${GENKEY_OBJ}: ${GENKEY_INC} config.mk
${CLIENT_OBJ}: ${CLIENT_INC} config.mk
${TEST_OBJ}: ${TEST_INC} config.mk

${LIBA}: ${OBJ}
	@echo AR
	@${AR} -rcs $@ ${OBJ}

${LIBSO}: ${OBJ}
	@echo CC $<
	@${CC} ${LDFLAGS} -o ${@} ${OBJ}

${GENKEY}: ${GENKEY_OBJ} ${LIBA}
	@echo CC -o $@
	@${CC} -o $@ ${GENKEY_OBJ} ${GENKEY_LDFLAGS}

${CLIENT}: ${CLIENT_OBJ} ${LIBA}
	@echo CC -o $@
	@${CC} -o $@ ${CLIENT_OBJ} ${CLIENT_LDFLAGS}

${TEST}: ${TEST_OBJ} ${LIBA}
	@echo CC -o $@
	@${CC} -o $@ ${TEST_OBJ} -lgcrypt

check: ${TEST}
	@./${TEST}

doc: Doxyfile
	@echo DOXYGEN
	@${DOXYGEN} >/dev/null

structs: ${CLIENT}
	@echo measuring structs
	@pahole ${CLIENT} >structsizes

clean:
	@echo cleaning
	@rm -f ${LIBA} ${LIBSO} ${GENKEY} ${CLIENT} ${OBJ} ${CLIENT_OBJ} ${TEST} ${TEST_OBJ}

dist:
	@echo creating dist tarball
	@mkdir -p libgotr-${VERSION}
	@cp -R ../LICENSE Makefile config.mk \
		${SRC} ${GENKEY_SRC} ${CLIENT_SRC} ${TEST_SRC} ${INC} ${TEST_INC} \
		libgotr-${VERSION}
	@tar -cf - libgotr-${VERSION} | gzip -c > libgotr-${VERSION}.tar.gz
	@rm -rf libgotr-${VERSION}

install: all
	@echo installing library files to ${DESTDIR}${PREFIX}/lib
	@mkdir -p ${DESTDIR}${PREFIX}/lib
	@cp -f ${LIBSO} ${DESTDIR}${PREFIX}/lib
	@chmod 755 ${DESTDIR}${PREFIX}/lib/${LIBSO}
	@/sbin/ldconfig -n ${DESTDIR}${PREFIX}/lib
	@cp -f ${LIBA} ${DESTDIR}${PREFIX}/lib
	@chmod 644 ${DESTDIR}${PREFIX}/lib/${LIBA}
	@echo installing genkey binary to ${DESTDIR}${PREFIX}/bin
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	@cp -f ${GENKEY} ${DESTDIR}${PREFIX}/bin
	@chmod 755 ${DESTDIR}${PREFIX}/bin/${GENKEY}
	@echo installing header files to ${DESTDIR}${PREFIX}/include
	@mkdir -p ${DESTDIR}${PREFIX}/include
	@cp -f gotr.h ${DESTDIR}${PREFIX}/include
	@chmod 644 ${DESTDIR}${PREFIX}/include/gotr.h

uninstall:
	@echo removing library files from ${DESTDIR}${PREFIX}/lib
	@rm -f ${DESTDIR}${PREFIX}/lib/${LIBSO}
	@rm -f ${DESTDIR}${PREFIX}/lib/${LIBA}
	@echo removing genkey binary from ${DESTDIR}${PREFIX}/bin
	@rm -f ${DESTDIR}${PREFIX}/bin/${GENKEY}
	@echo removing header files from ${DESTDIR}${PREFIX}/include
	@rm -f ${DESTDIR}${PREFIX}/include/gotr.h

.PHONY: all genkey client libgotr.a options doc clean structs
