
%{
	#include <stdio.h>
	#include "syscalls.h"
	#include "hashtable.h"

	int pplex(void);
	void pperror(char*);

	struct parameter_type params[MAX_PARAM_COUNT];
	int pcount = 0;
	extern int pplineno;
%}

%union {char *s; int d;}

%token POUNDDEF POUNDUNK TOKEN_NTSYSAPI TOKEN_WINAPI 
%token TOKEN_LPAREN TOKEN_RPAREN TOKEN_COMMA TOKEN_STAR TOKEN_SEMI
%token TOKEN_CDECL
%token <s> TOKEN_NTSTATUS
%token <s> WORD 
%token <d> NUMBER

%%

goodline: 
	goodline line
	| line
	;

line: preamble apidec
	;

preamble: TOKEN_NTSYSAPI wordlist TOKEN_WINAPI
	| TOKEN_NTSYSAPI wordlist TOKEN_CDECL
	;

wordlist: wordlist WORD
	| wordlist TOKEN_STAR
	| WORD
	| TOKEN_NTSTATUS
	;

apidec: WORD TOKEN_LPAREN paramlist TOKEN_RPAREN TOKEN_SEMI
	{
		int i;
		struct nt_syscall_info *call_info = NULL;

		call_info = (struct nt_syscall_info*)
			hashtable_search(nt_syscall_table, $1);

		if(call_info != NULL)
		{
			call_info->parameter_count = pcount;
			for(i = 0; i < pcount; i++) 
			{
				call_info->params[i].type = params[i].type;
				call_info->params[i].indirection = 
					params[i].indirection;

				/*printf("Param Type: %s, indirections: %d\n",*/
						/*call_info->params[i].type,*/
						/*call_info->params[i].indirection);*/
			}
			/*printf("%s: %d params\n", $1, pcount);*/
		}

		pcount = 0;
	}
	;

paramlist: paramlist TOKEN_COMMA param
	| paramlist TOKEN_COMMA
	| param
	| 
	;

param: param TOKEN_STAR
	{
		params[pcount-1].indirection++;
	}
	| param WORD
	| param TOKEN_NTSTATUS
	| WORD
	{
		params[pcount].indirection = 0;
		params[pcount].type= $1;
		pcount++;
	}
	| TOKEN_NTSTATUS
	{
		params[pcount].indirection = 0;
		params[pcount].type = $1;
		pcount++;
	}
	;

%%

void pperror(char *s) 
{
	fprintf(stderr, "error: %s, line: %d\n", s, pplineno);
}

