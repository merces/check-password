check-password
==============

check-password is an example ppolicy module to enforce strength passwords checks in OpenLDAP

## Compiling

1. Download the correct source code package from OpenLDAP website.

2. Extract it in the target machine and use OpenLDAP's Makefile to generate
some required headers:

	$ tar xf openldap-*.tar.gz
	$ cd opendalp*
	$ ./configure --enable-bdb=no --enable-hdb=no 
	$ make depend

We just disable BDB/HDB dependency to make things easier. It doesn't
affect your real OpenLDAP installation.

3. Now enter check-password module directory and call make, passing the OpenLDAP source
code path through LDAP_SRC variable. For example:

	$ LDAP_SRC=/home/myuser/openldap-2.4.40 make

You may also want to configure module destination path and configuration file path together
with make invocation:

	$ DEST=/usr/lib/ldap/modules CONF_FILE_PATH=/etc/ldap/check_password.conf LDAP_SRC=/home/myuser/openldap-2.4.40 make

## Installing

	# make install

## Configuring

1. Configure basic options in the config file defined by the variable CONF_FILE_PATH
2. Set the pwdCheckQuality attribute on ppolicy to either 1 or 2
3. Set pwdCheckModule attribute with module file path (.so)
