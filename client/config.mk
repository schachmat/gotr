# Customize below to fit your system

# includes and libs
INCS = -I. -I/usr/include
LIBS = -L/usr/lib -lc

# flags
CFLAGS = -g -std=c99 -pedantic -Wall -O0 ${INCS}
#CFLAGS = -std=c99 -pedantic -Wall -O3 ${INCS}
LDFLAGS = -g ${LIBS}
#LDFLAGS = -s ${LIBS}

# compiler and linker
CC = cc
