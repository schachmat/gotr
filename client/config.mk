# Customize below to fit your system

# includes and libs
INCS = -I. -I/usr/include -I../libgotr -I../libgotr/include
LIBS = -L/usr/lib -lc -L../libgotr -lgotr

# flags
CPPFLAGS = -D_XOPEN_SOURCE=600
CFLAGS = -g -std=c99 -pedantic -Wall -O0 ${INCS} ${CPPFLAGS}
#CFLAGS = -std=c99 -pedantic -Wall -O3 ${INCS} ${CPPFLAGS}
LDFLAGS = -g ${LIBS}
#LDFLAGS = -s ${LIBS}

# compiler and linker
CC = cc
