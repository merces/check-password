/*
	check_password - Módulo de checagem de senhas para ppolicy

	Author: Fernando Mercês (fernando@mentebinaria.com.br)

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

#define MAX_LINE 51
#define MAX_LOGFILE 201
#define MAX_LOG_MSG 61

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

	fprintf(fp, "%s - %s\n", now, s);
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


/*
	Function mmfstrcasestr()
	Author: Marcelo M. Fleury (marcelomf@gmail.com)
*/
char *mmfstrcasestr(const char *haystack, char *needle)
{
	char *cpyResult, *originHayStack = (char *) haystack;
	char *cpyHaystackLower;
	char *cpyNeedleLower;
	int numberOfAddress, i = 0;

	if(haystack == NULL || needle == NULL)
		return NULL;

	cpyHaystackLower = malloc(sizeof(char)*(strlen(haystack)+1));
	if(cpyHaystackLower == NULL)
		return NULL;

	cpyNeedleLower = malloc(sizeof(char)*(strlen(needle)+1));
	if(cpyNeedleLower == NULL)
		return NULL;

	memset(cpyHaystackLower, '\0', sizeof(char)*(strlen(haystack)+1));
	memset(cpyNeedleLower, '\0', sizeof(char)*(strlen(needle)+1));

	for(i = 0; *haystack; haystack++, i++)
		cpyHaystackLower[i] = tolower(*haystack);

	for(i = 0; *needle; needle++, i++)
		cpyNeedleLower[i] = tolower(*needle);

	cpyResult = strstr(cpyHaystackLower, cpyNeedleLower);

	if(cpyResult == NULL)
	{
		free(cpyHaystackLower);
		free(cpyNeedleLower);
		return NULL;
	}
	else
	{
		numberOfAddress = (cpyResult-cpyHaystackLower);
		free(cpyHaystackLower);
		free(cpyNeedleLower);
		return originHayStack += numberOfAddress;
	}
}

/* Regras (a), (b), (c), (d) e (f) (g)*/
static int basic_rules(const char *pw)
{
	char c = '\0';
	int lower, upper, digit, size, i;

	if (pw == NULL)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: senha vazia");
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
			snprintf(msg, MAX_LOG_MSG, "erro: tamanho da senha (%d) menor que 6", size);
			logit(msg);
		}
		return 0;
	}

	if (size > 8)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: tamanho da senha (%d) maior que 8", size);
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
				snprintf(msg, MAX_LOG_MSG, "erro: caractere %c nao e alfanumerico", pw[i]);
				logit(msg);
			}
			return 0;
		}
		if (c == (char) tolower(pw[i]))
		{
			if (config.log)
			{
				snprintf(msg, MAX_LOG_MSG, "erro: caractere %c repetido em sequencia", pw[i]);
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
			snprintf(msg, MAX_LOG_MSG, "erro: nao ha nenhum caractere minusculo");
			logit(msg);
		}
		return 0;
	}
	if (upper < 1)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: nao ha nenhum caractere maiusculo na senha");
			logit(msg);
		}
		return 0;
	}
	if (digit < 1)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: nao ha nenhum digito na senha");
			logit(msg);
		}
		return 0;
	}

	if (mmfstrcasestr(pw, "senha"))
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: senha possui a palavra \"senha\"");
			logit(msg);
		}
		return 0;
	}

	return 1;
}

/* Regra (e) */
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
					snprintf(msg, MAX_LOG_MSG, "erro: senha possui sequencia de teclado");
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
	char ano[] = "0000";
	char mname[] = "Xxx";
	char mnum[]= "00";

	(void) time(&now);
	d = localtime(&now);

	(void) strftime(ano, 5, "%Y", d);
	(void) strftime(mname, 4, "%b", d);
	(void) strftime(mnum, 3, "%m", d);

	if (strstr(pw, ano))
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: senha possui o ano atual (%s)", ano);
			logit(msg);
		}
		return 0;
	}
	if (mmfstrcasestr(pw, mname))
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: senha possui o nome do mes atual (%s)", mname);
			logit(msg);
		}
		return 0;
	}
	if (strstr(pw, mnum)) 
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: senha possui o numero do mes atual (%s)", mnum);
			logit(msg);
		}
		return 0;
	}

	return 1;
}

static int checkusername(const char *dn, const char *pw)
{
	char *igual = strchr(dn, '=');
	char nome[5];
	register int i;

	if (!igual)
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: recebido dn vazio");
			logit(msg);
		}
		return 0;
	}

	for (i=0; i<4; i++)
		nome[i] = *(igual+i+1);
	nome[4] = '\0';

	if (mmfstrcasestr(pw, nome))
	{
		if (config.log)
		{
			snprintf(msg, MAX_LOG_MSG, "erro: senha possui o nome de usuario");
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
