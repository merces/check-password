# check-password

check-password is ppolicy module used to enforce strong password checks in
OpenLDAP

## Compiling

1. Download the appropriate source code package for your system from the
   [OpenLDAP website](https://www.openldap.org).

2. Extract it on the target machine and use OpenLDAP’s Makefile to generate the
   required headers:

```shell
tar xf openldap-*.tgz
cd opendalp*
./configure
make depend
```

3. Now enter the check-password module directory and run `make`, passing the
   OpenLDAP source code path through the `LDAP_SRC` variable. For example:

```shell
LDAP_SRC=/home/myuser/openldap-2.6.12 make
```

You may also want to configure the module destination path and the configuration
file path together with the `make` invocation:

```shell
DEST=/usr/lib/ldap/modules CONF_FILE_PATH=/etc/ldap/check_password.conf LDAP_SRC=/home/myuser/openldap-2.4.40 make
```

## Installing

```shell
make install
```

## Configuration

1. Configure basic options in the config file specified by the `CONF_FILE_PATH`
   variable.
2. Set the `pwdCheckQuality` attribute in **ppolicy** to either **1** or **2**.
3. Set the `pwdCheckModule` attribute to the path of the module file (`.so`).
