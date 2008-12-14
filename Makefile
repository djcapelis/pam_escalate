CC=gcc
CFLAGS=-g -O0 -Wall -Wextra
LDFLAGS=-lpam -lpam_misc
SRCS=helpers.c pam_escalate.c
OBJS=helpers.o pam_escalate.o

all: pam_escalate

$(SRCS):
	$(CC) $(CFLAGS) -c $*.c

pam_escalate: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

install:

clean:
	rm $(OBJS) pam_escalate
