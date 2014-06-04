include config.mk

SRC = libgotr.c
LIB = libgotr.a
INC = libgotr.h
OBJ = ${SRC:.c=.o}

CLIENT = client
CLIENT_SRC = client.c
CLIENT_OBJ = ${CLIENT_SRC:.c=.o}

all: options ${LIB} ${CLIENT}

options:
	@echo build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ} ${CLIENT_OBJ}: ${INC} config.mk

${CLIENT}: ${CLIENT_OBJ} ${LIB}
	@echo CC -o $@
	@${CC} -o $@ ${CLIENT_OBJ} ${CLIENT_LDFLAGS}

${LIB}: ${OBJ}
	@echo AR
	@${AR} -rcs $@ ${OBJ}

clean:
	@echo cleaning
	@rm -f ${LIB} ${CLIENT} ${OBJ} ${CLIENT_OBJ}

.PHONY: all client libgotr.a options clean
