include config.mk

SRC = messaging.c gotr.c util.c gka.c b64.c crypto.c key.c
LIB = libgotr.a
INC = messaging.h gotr.h util.h gka.h b64.h crypto.h key.h user.h
OBJ = ${SRC:.c=.o}

CLIENT = client
CLIENT_SRC = client.c
CLIENT_INC = gotr.h
CLIENT_OBJ = ${CLIENT_SRC:.c=.o}

TEST = test
TEST_SRC = test.c
TEST_INC = test.h
TEST_OBJ = ${TEST_SRC:.c=.o}

all: options cscope ${LIB} ${CLIENT}

options:
	@echo build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ}: ${INC} config.mk
${CLIENT_OBJ}: ${CLIENT_INC} config.mk
${TEST_OBJ}: ${TEST_INC} config.mk

${LIB}: ${OBJ}
	@echo AR
	@${AR} -rcs $@ ${OBJ}

${CLIENT}: ${CLIENT_OBJ} ${LIB}
	@echo CC -o $@
	@${CC} -o $@ ${CLIENT_OBJ} ${CLIENT_LDFLAGS}

${TEST}: ${TEST_OBJ} ${LIB}
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
	@rm -f ${LIB} ${CLIENT} ${OBJ} ${CLIENT_OBJ} ${TEST} ${TEST_OBJ}

.PHONY: all client libgotr.a options cscope doc clean structs
