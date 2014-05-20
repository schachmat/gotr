include config.mk

SRC = libgotr.c
LIB = libgotr.a
INC = libgotr.h
OBJ = ${SRC:.c=.o}

all: options libgotr.a

options:
	@echo libgotr build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ}: ${INC} config.mk

${LIB}: ${OBJ}
	@echo AR
	@${AR} -rcs $@ ${OBJ}

clean:
	@echo cleaning
	@rm -f libgotr.a ${OBJ}

.PHONY: all options clean
