%{
	#include <stdio.h>
	#include <stdlib.h>
	#include "syscalls.h"
	#include "hashtable.h"

	int yylex(void);
	void yyerror(char*);
%}

%union {char *s; int d;}

%token POUNDDEF POUNDUNK 
%token <s> WORD 
%token <d> NUMBER

%%

lines:
	lines goodline
	| error 
	;

goodline:
	POUNDDEF WORD NUMBER	{
		if($3 < NT_SYSCALL_COUNT) 
		{
			struct nt_syscall_info* new_info = 
				(struct nt_syscall_info*)
				malloc(sizeof(struct nt_syscall_info));

			new_info->name = $2;
			new_info->number = $3;
			new_info->parameter_count = 0;
			new_info->handler = NULL;
			
			nt_syscalls[$3]=new_info;

			if(0 == hashtable_insert(nt_syscall_table, $2, new_info))
			{
				perror("Could not insert syscall info in hashtable ");
				exit(-1);
			}
			
		}
	}
	;

%%

void yyerror(char *s) 
{
	/*fprintf(stderr, "error: %s\n", s);*/
}

