# Makefile do check_password.c
# modulo do ppolicy para checagem de senhas

# Configuacao do caminho dos fontes do OpenLDAP
# E necessario compilar parcialmente o OpenLDAP neste
# caminho com ./configure && make depends
SLAPD_SOURCE=/usr/src/openldap-2.4.23
	
# Diretorio de destino do modulo
DEST=/usr/lib/ldap

# Caminho do arquivo de configuracao do modulo
CONF_FILE_PATH="/etc/ldap/check_password.conf"

# Caminhos das ferramentas necessarias
CC=/usr/bin/gcc
STRIP=/usr/bin/strip

# Nao alterar daqui em diante!
SRC=check_password.c
VERSION=1.5
CFLAGS=-O2 -W -Wextra -Wall -fpic -c
DFLAGS+=-D'CONF_FILE_PATH=$(CONF_FILE_PATH)'
INCLUDES=-I$(SLAPD_SOURCE)/include -I$(SLAPD_SOURCE)/servers/slapd
	
all:
	$(CC) $(CFLAGS) $(INCLUDES) $(DFLAGS) -o check_password.o $(SRC)
	$(CC) -shared -o check_password.so check_password.o
	
install:
	$(STRIP) check_password.so
	cp check_password.so $(DEST)/check_password.so.$(VERSION)
	chmod 0644 $(DEST)/check_password.so.$(VERSION)
	ln -sf $(DEST)/check_password.so.$(VERSION) $(DEST)/check_password.so
	
clean:
	rm -f check_password.so
	rm -f check_password.o
	
uninstall:
	rm -f $(DEST)/check_password.so.$(VERSION)
	rm -f $(DEST)/check_password.so
