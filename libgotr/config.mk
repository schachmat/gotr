# Customize below to fit your system

# includes and libs
INCS = -I. -I./include -I/usr/include
LIBS = -L/usr/lib -lc

CLIENT_LIBS = -L. -L/usr/lib -lc -lgotr

# flags
CFLAGS = -g -std=c99 -pedantic -Wall -O0 ${INCS} ${CPPFLAGS}
#CFLAGS = -std=c99 -pedantic -Wall -O3 ${INCS} ${CPPFLAGS}
LDFLAGS = -g ${LIBS}
#LDFLAGS = -s ${LIBS}

CLIENT_LDFLAGS = -g ${CLIENT_LIBS}
#CLIENT_LDFLAGS = -s ${CLIENT_LIBS}

# compiler and linker
CC = cc
AR = ar
