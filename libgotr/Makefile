include config.mk

SRC = libgotr_plugin.c libgotr.c util.c bdgka.c b64.c crypto.c
LIB = libgotr.a
INC = libgotr_plugin.h libgotr.h util.h bdgka.h b64.h crypto.h
OBJ = ${SRC:.c=.o}

CLIENT = client
CLIENT_SRC = client.c
CLIENT_INC = libgotr.h crypto.h
CLIENT_OBJ = ${CLIENT_SRC:.c=.o}

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

${CLIENT}: ${CLIENT_OBJ} ${LIB}
	@echo CC -o $@
	@${CC} -o $@ ${CLIENT_OBJ} ${CLIENT_LDFLAGS}

${LIB}: ${OBJ}
	@echo AR
	@${AR} -rcs $@ ${OBJ}

cscope: ${SRC} ${INC} ${CLIENT_SRC} ${CLIENT_INC}
	@echo cScope
	@${CSCOPE} -R -b

doc: Doxyfile
	@echo DOXYGEN
	@${DOXYGEN} >/dev/null

clean:
	@echo cleaning
	@rm -f ${LIB} ${CLIENT} ${OBJ} ${CLIENT_OBJ}

.PHONY: all client libgotr.a options cscope doc clean
