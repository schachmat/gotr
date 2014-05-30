# Customize below to fit your system

# includes and libs
INCS = -I. -I./include -I/usr/include
LIBS = -L./lib -L/usr/lib -lc -lnacl
NACL_LOCATION = "lib/libnacl.a"

# flags
CFLAGS = -g -pedantic -Wall -O0 ${INCS}
#CFLAGS = -pedantic -Wall -O3 ${INCS}
LDFLAGS = -g ${LIBS}
#LDFLAGS = -s ${LIBS}

# compiler and linker
CC = cc
AR = ar
