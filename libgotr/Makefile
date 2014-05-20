include config.mk

SRC = libgotr.c
OBJ = ${SRC:.c=.o}
LIB = libgotr.a

all: options libgotr

options:
	@echo libgotr build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ}: config.mk

${LIB}: ${OBJ}
	@echo AR
	@${AR} -rcs $@ ${OBJ}

clean:
	@echo cleaning
	@rm -f libgotr.a ${OBJ}

.PHONY: all options clean
