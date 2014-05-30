include config.mk

SRC = client.c
OBJ = ${SRC:.c=.o}

all: options client

options:
	@echo client build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

.c.o:
	@echo CC $<
	${CC} -c ${CFLAGS} $<

${OBJ}: config.mk

client: ${OBJ}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	@echo cleaning
	@rm -f client ${OBJ}

.PHONY: all options clean
