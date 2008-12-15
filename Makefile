CC=gcc
CFLAGS=-g -O0 -Wall -Wextra
LDFLAGS=-shared -lpam -lpam_misc
SRCS=pam_escalate.c
OBJS=pam_escalate.o

all: pam_escalate.so

$(SRCS):
	$(CC) $(CFLAGS) -c $*.c

pam_escalate.so: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

install:

clean:
	rm $(OBJS) pam_escalate
