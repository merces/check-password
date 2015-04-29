# OpenLDAP source code path
LDAP_SRC ?= /usr/src/openldap
	
# Module destination path
DEST ?= /lib/ldap

# check-password configuration file path
CONF_FILE_PATH ?= "/etc/check_password.conf"

CC ?= gcc
STRIP = strip

SRC=check_password.c
VERSION=1.5
CFLAGS=-O2 -W -Wextra -Wall -fpic -c
DFLAGS+=-D'CONF_FILE_PATH=$(CONF_FILE_PATH)' -D_GNU_SOURCE 
INCLUDES=-I$(LDAP_SRC)/include -I$(LDAP_SRC)/servers/slapd

all:
	$(CC) $(CFLAGS) $(INCLUDES) $(DFLAGS) -o check_password.o $(SRC)
	$(CC) -shared -o check_password.so check_password.o

install:
	$(STRIP) check_password.so
	cp check_password.so $(DEST)/check_password.so.$(VERSION)
	chmod 0644 $(DEST)/check_password.so.$(VERSION)
	ln -sf $(DEST)/check_password.so.$(VERSION) $(DEST)/check_password.so

clean:
	rm -f check_password.o
	rm -f check_password.so

uninstall:
	rm -f $(DEST)/check_password.so.$(VERSION)
	rm -f $(DEST)/check_password.so
