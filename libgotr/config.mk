# Customize below to fit your system

# paths
PREFIX = /usr/local

# includes and libs
INCS = -I. -I./include -I/usr/include
LIBS = -L/usr/lib -lc -lgcrypt

CLIENT_LIBS = -L. -L/usr/lib -lc -lgotr -lgcrypt

# flags
CPPFLAGS = -DLGOTR_VERSION_MAJOR=\"${MAJOR}\" -DLGOTR_VERSION_MINOR=\"${MINOR}\" -DGOTR_GCRYPT_VERSION=\"1.6.1\" -D_DEFAULT_SOURCE
CFLAGS = -g -std=c99 -fPIC -pedantic -Wall -O0 ${INCS} ${CPPFLAGS}
#CFLAGS = -std=c99 -fPIC -pedantic -Wall -O3 ${INCS} ${CPPFLAGS}
LDFLAGS = -g -shared -Wl,-soname,libgotr.so.${MAJOR} ${LIBS}
#LDFLAGS = -shared -Wl,-soname,libgotr.so.${MAJOR} ${LIBS}

GENKEY_LDFLAGS = -g ${CLIENT_LIBS}
#GENKEY_LDFLAGS = -s ${CLIENT_LIBS}
CLIENT_LDFLAGS = -g ${CLIENT_LIBS}
#CLIENT_LDFLAGS = -s ${CLIENT_LIBS}

# compiler and linker
CC = cc
AR = ar
DOXYGEN = doxygen
