%{
extern int main(int argc, char* argv[]);
#include <stdio.h>
#include "ntapi.tab.h"
%}

%%
[0-9]+	yylval.d=atoi(yytext); return NUMBER;
\#define	return POUNDDEF;
\#[a-zA-Z0-9]+
[A-Za-z][a-zA-Z0-9]*	yylval.s=strdup(yytext); return WORD;
.
\n
%%

int yywrap(void)
{
	return 1;
}
