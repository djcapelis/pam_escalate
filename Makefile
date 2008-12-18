CC=gcc
CFLAGS=-g -O0 -Wall -Wextra
LDFLAGS=-shared -lpam -lpam_misc
SRCS=pam_escalate.c

all: pam_escalate.so

pam_escalate.so: $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

install:
	install -m 644 -o root pam_escalate.so /lib/security/

clean:
	rm pam_escalate.so
