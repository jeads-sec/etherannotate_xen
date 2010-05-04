#include <wchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <errno.h>
#include <xenctrl.h> 
#include <unistd.h>
#include "ConvertUTF.h"
#include "parameters.h"
#include "hashtable.h"

#define MAX_PARAMETER_HANDLERS 1024

struct hashtable* nt_parameter_handlers = NULL;

void base16_print(const char *str)
{
	int length = strlen(str);
	int item, i;

	for(i = 0; i < length; i++)
	{
		item = (unsigned int)str[i];
		printf("%02X", item);
	}
}

int parameter_handling_init(void)
{
	nt_parameter_handlers = 
		create_hashtable(MAX_PARAMETER_HANDLERS, hash_fn, string_equality_fn);

	if(nt_parameter_handlers == NULL)
	{
		return -1;
	}

	parameter_handler_add("UNICODE_STRING", unicode_string_handler);
	parameter_handler_add("PUNICODE_STRING", unicode_string_handler);
	parameter_handler_add("OBJECT_ATTRIBUTES", object_attributes_handler);
	parameter_handler_add("POBJECT_ATTRIBUTES", object_attributes_handler);
	parameter_handler_add("LARGE_INTEGER", large_integer_handler);
	parameter_handler_add("PLARGE_INTEGER", large_integer_handler);
	parameter_handler_add("ULARGE_INTEGER", ularge_integer_handler);
	parameter_handler_add("PULARGE_INTEGER", ularge_integer_handler);
	parameter_handler_add("PLONG", plong_handler);
	parameter_handler_add("PULONG", pulong_handler);
	parameter_handler_add("SIZE_T", sizet_handler);
	parameter_handler_add("PHANDLE", phandle_handler);
	parameter_handler_add("void", void_handler);
	/*parameter_handler_add("PLPC_MESSAGE", port_message_handler);*/

	return 0;
}

int parameter_handler_add(char* type, param_handler_func fp)
{
	if (0 == 
		hashtable_insert(nt_parameter_handlers, 
			type, fp))
	{
		perror("Could not insert syscall info in hashtable ");
		return -1;
	}
	return 0;
}

int parameter_handler_do(struct parameter_type *param, unsigned long address)
{
	/* look up the parameter name in a hash table to find
	 * decoder function */
	param_handler_func fp;

	fp = (param_handler_func)hashtable_search(nt_parameter_handlers,
			param->type);

	if(fp != NULL)
	{
		return (*fp)(param, address);
	}
	else
	{
		return -1;
	}
}

int parameter_handler_cleanup(void)
{
	hashtable_destroy(nt_syscall_table, 1);
	return 0;
}

unsigned long parameter_handler_dereference(struct parameter_type *param, unsigned long address)
{
	int indirections = param->indirection;
	unsigned long new_address = address;

	while(indirections > 1)
	{

		domain_read_current(address, &new_address, sizeof(uint32_t));
		address = new_address;
		if(address == 0)
			break;

		indirections--;
	}

	if(address == 0)
	{
		printf("Could not dereference guest pointer! (levels: %d)\n", 
				param->indirection);
	}
	return address;
}

int basic_type_handler(int size, void *buffer,  struct parameter_type *param, unsigned long address) 
{
	int read_success = -1;
	if(address == 0)
		return 0;

	unsigned long final_address = parameter_handler_dereference(param, address);

	read_success = domain_read_current(final_address, buffer, 
			size);

	if(read_success >= 0) 
	{
		return read_success;
	}
	else
	{
		return -1;
	}
}

/* HANDLE is just a typedef for void* */
int phandle_handler(struct parameter_type *param, unsigned long address)
{
	/* windows 32-bit pointer */
	uint32_t pointer;
	int did_read = -1;

	did_read = basic_type_handler(sizeof(uint32_t), &pointer, param, address);
	if(did_read >= 0)
	{
		printf(": 0x%x", pointer);
		return 0;
	}
	else
	{
		return -1;
	}
}

int void_handler(struct parameter_type *param, unsigned long address)
{
	if(param->indirection > 1)
	{
		return phandle_handler(param, address);
	}
	else
	{
		/* normal void* shouldn't
		 * print anything extra
		 * for now.
		 *
		 * this will be a data handler
		 * (perhaps)
		 */
		return 0;
	}
}


int plong_handler(struct parameter_type *param, unsigned long address)
{
	/* windows 32-bit longs */
	int32_t win_long = 0;
	int did_read = -1;

	did_read = basic_type_handler(sizeof(int32_t), &win_long, param, address);
	if(did_read >= 0)
	{
		printf(": %d", win_long);
		return 0;
	}
	else
	{
		return -1;
	}
}

int pulong_handler(struct parameter_type *param, unsigned long address)
{
	/* windows 32-bit unsigned longs */
	uint32_t win_ulong = 0;
	int did_read = -1;

	did_read = basic_type_handler(sizeof(uint32_t), &win_ulong, param, address);
	if(did_read >= 0)
	{
		printf(": %u", win_ulong);
		return 0;
	}
	else
	{
		return -1;
	}
}

int sizet_handler(struct parameter_type *param, unsigned long address)
{
	if(param->indirection >= 1)
	{
		return pulong_handler(param, address);
	}
	else
	{
		/* the number itself is fine */
		return 0;
	}
}

int large_integer_handler(struct parameter_type *param, unsigned long address)
{
	/* windows 64 bit large integer */
	int64_t win_long = 0;
	int did_read = -1;

	did_read = basic_type_handler(sizeof(int64_t), &win_long, param, address);
	if(did_read >= 0)
	{
		printf(": %ld", win_long);
		return 0;
	}
	else
	{
		return -1;
	}
}

int ularge_integer_handler(struct parameter_type *param, unsigned long address)
{
	/* windows 64 bit large integer */
	uint64_t win_long = 0;
	int did_read = -1;

	did_read = basic_type_handler(sizeof(uint64_t), &win_long, param, address);
	if(did_read >= 0)
	{
		printf(": %lu", win_long);
		return 0;
	}
	else
	{
		return -1;
	}
}


char* convert_unicode_string(int length, uint32_t string_pointer)
{
	UTF16 *wstring;
	UTF16 *wstring_start;
	UTF8 *astring;
	UTF8 *astring_start;
	char* retval = NULL;
	
	ConversionResult convert_result;

	wstring = (UTF16*)malloc(sizeof(UTF16) * length);
	astring = (UTF8*)malloc(sizeof(UTF8) * length * 2);

	domain_read_current(string_pointer, wstring, sizeof(UTF16)*length);

	wstring_start = wstring;
	UTF16 **ptr_to_wstring = &wstring_start;
	astring_start = astring;
	UTF8 **ptr_to_astring = &astring_start;

	convert_result = ConvertUTF16toUTF8(ptr_to_wstring, &wstring[length], 
			ptr_to_astring, &astring[length*2], lenientConversion);


	if(convert_result != conversionOK)
	{
		free(astring);
		retval = NULL;
	}
	else
	{
		retval = (char*)astring;
	}

	free(wstring);
	return retval;
}

/* REMEMBER TO FREE RETURNED STRING! */
char* winnt_read_unicode_string(unsigned long address)
{
	struct unicode_string {
		unsigned short length;
		unsigned short max_length;
		uint32_t wstring;
	} __attribute__ ((packed));

	char* retval = NULL;

	struct unicode_string str;

	domain_read_current(address, &str, sizeof(struct unicode_string));
	/*printf("Unicode String Info: len: %hd, maxlen: %hd, ptr: 0x%x\n",*/
	/*str.length, str.max_length, str.wstring);*/

	if (str.length < 512 && str.wstring != 0)
	{
		retval = convert_unicode_string(str.length, str.wstring);
	}

	return retval;
}

int unicode_string_handler(struct parameter_type *param, unsigned long address) 
{ 
	if(address == 0)
		return 0;

	unsigned long final_address = parameter_handler_dereference(param, address);

	char* display_string = winnt_read_unicode_string(final_address);
	if(display_string != NULL)
	{

		printf(": ");
		base16_print(display_string);
		free(display_string);
	}
	else
	{
		return -1;
	}
	return 0;
}

/*int port_message_handler(struct parameter_type *param, unsigned long address)*/
/*{*/
	/*struct port_message {*/
		/*uint16_t data_length;*/
		/*uint16_t length;*/
		/*uint16_t message_type;*/
		/*uint16_t virtual_range_offset;*/
		/*uint32_t client_id;*/
		/*uint32_t message_id;*/
		/*uint32_t callback_id;*/
		/*char data[328];*/
	/*} __attribute__ ((packed));*/



	/*struct port_message message;*/

	/*unsigned long final_address = address;*/

	/*domain_read_current(final_address, &message, sizeof(struct port_message));*/

	
	/* 0x90241 = magic DNS client id */

	/*uint16_t length = 0;*/
	/*uint32_t magic = 0;*/
	/* read magic dword */
	/*domain_read_current(final_address+20+8, &magic, sizeof(uint32_t));*/
	/*if(magic == 0x90241)*/
	/*{*/

		/*domain_read_current(final_address+20+0x34, &length, sizeof(uint16_t));*/

		/*char* dns_name =*/
			/*convert_unicode_string(length, final_address+20+0x38);*/

		/*if(dns_name != NULL)*/
		/*{*/
			/*printf(": [DNS REQUEST: ");*/
			/*base16_print(dns_name);*/
			/*printf("]");*/
			/*free(dns_name);*/
			/*return 0;*/
		/*}*/
		/*else*/
		/*{*/
			/*return -1;*/
		/*}*/
	/*}*/


	
	/*return 0;*/

/*}*/

int object_attributes_handler(struct parameter_type *param, unsigned long address)
{
	if(address == 0)
		return 0;

	unsigned long final_address = parameter_handler_dereference(param, address);

	struct object_attributes {
		uint32_t length;
		uint32_t handle;
		uint32_t unicode_string_ptr;
		uint32_t attributes;
		uint32_t sec_descriptor_ptr;
		uint32_t sec_qos_ptr;
	} __attribute__ ((packed));

	struct object_attributes attributes;
	char* display_string;

	domain_read_current(final_address, &attributes, sizeof(struct object_attributes));

	if(attributes.unicode_string_ptr == 0)
		return 0;

	display_string = winnt_read_unicode_string((unsigned long)attributes.unicode_string_ptr);

	if(display_string != NULL)
	{

		printf(": ");
		base16_print(display_string);
		free(display_string);
	}
	else
	{
		return -1;
	}

	return 0;
	
}
