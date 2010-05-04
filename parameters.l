
%{
//extern int main(int argc, char* argv[]);
#include <stdio.h>
#include "pp.parameters.h"
//[A-Za-z][a-zA-Z0-9]*	pplval.s=strdup(pptext); return WORD;
//#[0-9]+	pplval.d=atoi(pptext); return NUMBER;
%}

%%
#[0-9]+	pplval.d=atoi(pptext); return NUMBER;
\#define	return POUNDDEF;
NTSTATUS	pplval.s=strdup("NTSTATUS"); return TOKEN_NTSTATUS;
NTSYSAPI	return TOKEN_NTSYSAPI;
WINAPI		return TOKEN_WINAPI;
__cdecl		return TOKEN_CDECL;
\(		return TOKEN_LPAREN;
\)		return TOKEN_RPAREN;
\,		return TOKEN_COMMA;
\*		return TOKEN_STAR;
\;		return TOKEN_SEMI;
\#[a-zA-Z0-9]+
const
[A-Za-z][a-zA-Z0-9_]*	pplval.s=strdup(pptext); return WORD;
.
\n
%%

int ppwrap(void)
{
	return 1;
}
