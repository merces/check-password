/*
    check_password - ppolicy password checking module for OpenLDAP

    Copyright (C) 2012-2015 Fernando Mercês <nandu88 *noSPAM* gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <portable.h>
#include <slap.h>

#define MAX_LINE 60
#define MAX_LOGFILE 250
#define MAX_LOG_MSG 150

struct config
{
   char log;
   char logfile[MAX_LOGFILE];
} config;

char msg[MAX_LOG_MSG];

void logit(char s[])
{
	FILE *fp;
	const time_t timer = time(NULL);
	char *now = ctime(&timer);

	if (!config.log || config.logfile[0] == '\0')
		return;

	fp = fopen(config.logfile, "a");

	if (fp == NULL)
		return;

	if (now)
		now[strlen(now)-1] = '\0';	

	fprintf(fp, "error: %s - %s\n", now, s);
	fclose(fp);
}

void loadconfig()
{
   FILE *fp;
   char line[MAX_LINE];
   char *param, *value;
   int i;

#ifdef CONF_FILE_PATH
fp = fopen(CONF_FILE_PATH, "r");
#else
fp = fopen("check_password.conf", "r");
#endif

   if (fp == NULL)
      return;

	config.log = config.logfile[0] = 0;

   while (fgets(line, MAX_LINE, fp))
   {
      // comments
      if (*line == '#')
         continue;

      // remove newline
      for (i=0; i<MAX_LINE; i++)
      {   
         if (line[i] == '\n' || i == MAX_LINE-1)
         {   
            line[i] = '\0';
            break;
         }
      }

      param = strtok(line, "=");
      value = strtok(NULL, "=");

      if (param && (strcmp("log", param) == 0))
      {
         if (value && (strcmp("true", value) == 0))
            config.log = 1;
      }
      else if (param && (strcmp("logfile", param) == 0))
      {
         if (value)
            strncpy(config.logfile, value, MAX_LOGFILE);
      }
   }
	fclose(fp);
}

static int basic_rules(const char *pw)
{
	char c = '\0';
	int lower, upper, digit, size, i;

	if (pw == NULL)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "empty password");
			logit(msg);
		}
		return 0;
	}

	lower = upper = digit = 0;
	size = (int) strlen(pw);

	if (size < 6)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "password length (%d) is lower than 6", size);
			logit(msg);
		}
		return 0;
	}

	if (size > 8)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "password length (%d) is bigger than 8", size);
			logit(msg);
		}
		return 0;
	}

	for (i=0; i<size; i++)
	{
		if (! isalnum(pw[i]))
		{
			if (config.log)
			{
				snprintf(msg, MAX_LOG_MSG, "character %c is not alpha-numeric", pw[i]);
				logit(msg);
			}
			return 0;
		}
		if (c == (char) tolower(pw[i]))
		{
			if (config.log)
			{
				snprintf(msg, MAX_LOG_MSG, "character %c repeated sequentially", pw[i]);
				logit(msg);
			}
			return 0;
		}
		if (islower(pw[i])) lower++;
		if (isupper(pw[i])) upper++;
		if (isdigit(pw[i])) digit++;
		c = tolower(pw[i]);
	}

	if (lower < 1)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "no lower-case characters");
			logit(msg);
		}
		return 0;
	}
	if (upper < 1)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "no upper-case characters");
			logit(msg);
		}
		return 0;
	}
	if (digit < 1)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "no numbers");
			logit(msg);
		}
		return 0;
	}

	if (strcasestr(pw, "password"))
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "password contains the word \"password\"");
			logit(msg);
		}
		return 0;
	}

	return 1;
}

static int keyboard_seq(const char *pw)
{
	const char kbseq[] = "qwertyuiopasdfghjklzxcvbnm1234567890";
	const char kbqes[] = "0987654321mnbvcxzlkjhgfdsapoiuytrewq";
	char needle[4];
	register int i, j;

	for (i=0; i < (int) strlen(pw)-2; i++)
	{
		needle[0] = tolower(pw[i]);
		needle[1] = tolower(pw[i+1]);
		needle[2] = tolower(pw[i+2]);
		needle[3] = '\0';

		for (j=0; j < (int) strlen(kbseq); j++)
		{
			if (strstr(kbseq, needle) != NULL || strstr(kbqes, needle) != NULL)
			{
				if (config.log)
				{
					snprintf(msg, MAX_LOG_MSG, "password contains a keyboard sequence");
					logit(msg);
				}
				return 0;
			}
		}
	}

	return 1;
}

static int checkdate(const char *pw)
{
	time_t now;
	struct tm *d;
	char year[] = "0000";
	char mname[] = "Xxx";
	char mnum[]= "00";

	(void) time(&now);
	d = localtime(&now);

	(void) strftime(year, 5, "%Y", d);
	(void) strftime(mname, 4, "%b", d);
	(void) strftime(mnum, 3, "%m", d);

	if (strstr(pw, year))
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "password contains the current year (%s)", year);
			logit(msg);
		}
		return 0;
	}
	if (strcasestr(pw, mname))
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "password contains the current month name (%s)", mname);
			logit(msg);
		}
		return 0;
	}
	if (strstr(pw, mnum)) 
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "password contains the current month number (%s)", mnum);
			logit(msg);
		}
		return 0;
	}

	return 1;
}

static int checkusername(const char *dn, const char *pw)
{
	char *equal = strchr(dn, '=');
	char nome[5];
	register int i;

	if (!equal)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "empty dn received");
			logit(msg);
		}
		return 0;
	}

	for (i=0; i<4; i++)
		nome[i] = *(equal+i+1);
	nome[4] = '\0';

	if (strcasestr(pw, nome))
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "password contains the username");
			logit(msg);
		}
		return 0;
	}
	return 1;
}

int check_password(const char *pPasswd, char **ppErrStr __attribute__((unused)), const Entry *pEntry)
{
	loadconfig();

	if (!basic_rules(pPasswd) || !keyboard_seq(pPasswd) ||
	    !checkdate(pPasswd) || !checkusername(pEntry->e_name.bv_val, pPasswd))
		return 1;

	return 0;
}
