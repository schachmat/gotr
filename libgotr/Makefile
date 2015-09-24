include config.mk

LIBA = libgotr.a
LIBSO = libgotr.so.${MAJOR}.${MINOR}
SRC = messaging.c gotr.c util.c gka.c b64.c crypto.c key.c
INC = messaging.h gotr.h util.h gka.h b64.h crypto.h key.h user.h
OBJ = ${SRC:.c=.o}

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

all: options cscope ${LIBA} ${LIBSO} ${GENKEY} ${CLIENT}

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

${GENKEY}: ${GENKEY_OBJ}
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

cscope: ${SRC} ${INC} ${CLIENT_SRC} ${CLIENT_INC} ${TEST_SRC} ${TEST_INC}
	@echo cScope
	@${CSCOPE} -R -b

doc: Doxyfile
	@echo DOXYGEN
	@${DOXYGEN} >/dev/null

structs: ${CLIENT}
	@echo measuring structs
	@pahole ${CLIENT} >structsizes

clean:
	@echo cleaning
	@rm -f ${LIBA} ${LIBSO} ${GENKEY} ${CLIENT} ${OBJ} ${CLIENT_OBJ} ${TEST} ${TEST_OBJ}

.PHONY: all genkey client libgotr.a options cscope doc clean structs
