CC=gcc
CFLAGS=-g -O2 -fPIC -Wall -Wextra -I/usr/include/security -I/usr/include/pam
LDFLAGS=-shared -lpam -lpam_misc
SRCS=pam_escalate.c

all: pam_escalate.so

pam_escalate.so: $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

install:
	install -m 644 -o root pam_escalate.so /lib/security/

installosx:
	install -m 644 -o root pam_escalate.so /usr/lib/pam/

clean:
	rm pam_escalate.so
