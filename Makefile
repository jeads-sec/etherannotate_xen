CC=gcc
CFLAGS=-g -c -Wall -O2
LDFLAGS=-lm -lxenctrl -ldisasm
SOURCES=ConvertUTF.c parameters.c syscalls.c hashtable.c saved_parameters.c unpack.c ether.c
OBJECTS=pp.parameters.o parameters.pp.o ntapi.tab.o lex.yy.o $(SOURCES:.c=.o) 
ETHER=ether

all:	clean $(ETHER) $(INSTRTRACE)

ntapi.tab.o: ntapi.y
	bison -v -d ntapi.y
	$(CC) $(CFLAGS) -o ntapi.tab.o ntapi.tab.c

lex.yy.o: ntapi.l
	flex ntapi.l
	$(CC) $(CFLAGS) -o lex.yy.o lex.yy.c

ether_main.o: ether_main.c
	$(CC) $(CFLAGS) -o ether_main.o ether_main.c

pp.parameters.o: parameters.y
	bison -v -d -p pp -o pp.parameters.c parameters.y
	$(CC) $(CFLAGS) -o pp.parameters.o pp.parameters.c

parameters.pp.o: parameters.l
	flex --prefix=pp -o parameters.pp.c parameters.l
	$(CC) $(CFLAGS) -o parameters.pp.o parameters.pp.c

$(ETHER): $(OBJECTS) ether_main.o
		 $(CC) $(LDFLAGS) $(OBJECTS) ether_main.o -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf ./*.o ./ether ./*.output ./*.pp.* ./pp.* ./*.tab.* ./*.yy.* *~
