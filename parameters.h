#ifndef __PARAMETERS_H_
#define __PARAMETERS_H_

#include "hashtable.h"
#include "syscalls.h"

extern struct hashtable* nt_parameter_handlers;
typedef int(*param_handler_func)(struct parameter_type *, unsigned long);

int parameter_handling_init(void);
int parameter_handler_add(char* type, param_handler_func fp);
int parameter_handler_do(struct parameter_type *param, unsigned long address);
int parameter_handler_cleanup(void);



int phandle_handler(struct parameter_type *param, unsigned long address);
int void_handler(struct parameter_type *param, unsigned long address);
int plong_handler(struct parameter_type *param, unsigned long address);
int pulong_handler(struct parameter_type *param, unsigned long address);
int ularge_integer_handler(struct parameter_type *param, unsigned long address);
int large_integer_handler(struct parameter_type *param, unsigned long address);
int port_message_handler(struct parameter_type *param, unsigned long address);
int sizet_handler(struct parameter_type *param, unsigned long address);

unsigned long parameter_handler_dereference(struct parameter_type *param, unsigned long address);
int unicode_string_handler(struct parameter_type *param, unsigned long address);
int object_attributes_handler(struct parameter_type *param, unsigned long address);
char* winnt_read_unicode_string(unsigned long address);
char* convert_unicode_string(int length, uint32_t string_pointer);


void base16_print(const char *str);
#endif
