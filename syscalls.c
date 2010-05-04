#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xenctrl.h>
#include <arpa/inet.h>
#include <xen/hvm/ether.h>
#include "hashtable.h"
#include "syscalls.h"
#include "ether_main.h"
#include "parameters.h"
#include "ntapi.tab.h"
#include "ether.h"

extern FILE *yyin;
extern void yyparse(void);
extern FILE *ppin;
extern void ppparse(void);

struct nt_syscall_info* nt_syscalls[NT_SYSCALL_COUNT]; 
struct hashtable* nt_syscall_table; 
/* hash function taken from description in:
 * http://www.cse.yorku.ca/~oz/hash.html
 *
 * according to the site the code is in the public domain *
 */
unsigned int hash_fn(void *value)
{
	const char* s_value = (const char*)value;
	unsigned int hash = 0;
	int c; 
	while ((c = *s_value++))
		hash = c + (hash << 6) + (hash << 16) - hash;

	return hash;
}

int string_equality_fn(void *s1, void *s2)
{
	return ( 0 == strcmp((const char*)s1, (const char *)s2));
}

/* populate the windows nt syscal table. Use this to map
 * from syscall# to syscall name
 * and to figure out the number of arguments
 * later this table can include more information about
 * the call arguments and derive their textual representation
 */
int nt_init_syscall_table(void) 
{
	nt_syscall_table = 
		create_hashtable(NT_SYSCALL_COUNT, hash_fn, string_equality_fn);

	sp_table = sp_init();

	if(nt_syscall_table == NULL)
	{
		return -1;
	}

	if(parameter_handling_init() < 0)
	{
		nt_free_syscalls();
		return -1;
	}

	if(sp_table == NULL)
	{
		nt_free_syscalls();
		return -2;
	}

	return 0;

}

/* parse the parameters to windodws nt system call arguments */
void nt_parse_parameters(void)
{
	FILE *syscall_defines = fopen("winternl.h", "r");
	ppin = syscall_defines;
	ppparse();
	fclose(syscall_defines);
}

/* populate the nt system call map and table from
 * winternl.h and nativeapi.h, respectively
 */
int nt_populate_syscalls(void) 
{
	FILE *nt_table = fopen("nativeapi.h", "r");
	int i;

	if(nt_init_syscall_table() < 0)
	{
		perror("Could not initialize system call tables ");
		return -2;
	}
	
	for( i = 0; i < NT_SYSCALL_COUNT; i++)
	{
		nt_syscalls[i] = NULL;
	}

	if(nt_table == NULL)
	{
		perror("Could not open nt syscall list");
		return -1;
	}

	yyin = nt_table;
	yyparse();
	fclose(nt_table);

	for( i = 0; i < NT_SYSCALL_COUNT; i++)
	{
		if(strncmp(nt_syscalls[i]->name, "NtDeviceIoControlFile", 21) == 0)
		{
			nt_syscalls[i]->handler = process_NtDeviceIoControlFile;
		}
		else if(strncmp(nt_syscalls[i]->name, "NtRequestWaitReplyPort", 22) == 0)
		{
			nt_syscalls[i]->handler = process_NtRequestWaitReplyPort;
		}
	}

	return 0;
}

void nt_free_syscalls(void)
{
	int i, j;
	for(i = 0; i < NT_SYSCALL_COUNT; i++)
	{
	       if(nt_syscalls[i] != NULL)
	       {
		       for(j = 0; j < MAX_PARAM_COUNT; j++)
		       {
			       if(nt_syscalls[i]->params[j].type != NULL)
			       {
				       free(nt_syscalls[i]->params[j].type);
			       }
		       }
	       }
	}

	parameter_handler_cleanup();
	sp_cleanup();
	
}


/* read 32 bits from the guest hvm domain. I had
 * to write this function since neither the default
 * xen xc_translate_foreign_address or xenaccess
 * worked with 64bit hvm domains. I don't know why
 * the libxc calls didn't work, but this method
 * should work on any hvm domain. All this does is
 * call a function in the hypervisor to read the memory
 * using the current pagetable of the requested domain
 * as the base for translation of va->mfn
 */
int domain_read_32bits( int xc_iface, int domid, unsigned long va, uint32_t *dest)
{
	if(ether_readguest(xc_iface,
				domid,
				va,
				(unsigned char*)dest,
				sizeof(uint32_t)) != 0)
	{
		return -1;
	}
	else
	{
		return 1;
	}

}

int domain_read_current(unsigned long va, void *dest, int length)
{
	if(ether_readguest(current_domain.xc_iface,
				current_domain.domid,
				va,
				(unsigned char*)dest,
				length) != 0)
	{
		return -1;
	}
	else
	{
		return 1;
	}
}

void process_generic_syscall(struct syscall_info *call, uint32_t *parameter_values)
{
	if(call->notification_type == SYSCALL_CALL)
	{
		printf("CALL ");
	}
	else
	{ 
		printf("RET 0x%lx = ", call->return_value);
	}

	printf("name: [%s], cr3: [0x%lx] pid: [%d], %s(",
			call->process_name,
			call->cr3,
			call->pid,
			nt_syscalls[call->number]->name);



	if( parameter_values != NULL)
	{
		int i = 0;

		for(i = 0; i < nt_syscalls[call->number]->parameter_count; i++)
		{
			uint32_t param = parameter_values[i];

			if(i != 0)
			{
				printf(", ");
			}

			printf("0x%x", param);
			/* parameter_values = memory address of parameter */
			parameter_handler_do(&(nt_syscalls[call->number]->params[i]), param);

		}
	}

	printf(")\n");
}

void process_NtDeviceIoControlFile(struct syscall_info *call, uint32_t *parameter_values)
{
	if(call->notification_type == SYSCALL_CALL && parameter_values != NULL)
	{
		if(parameter_values[5] == 0x12007)
		{
			uint16_t port;
			uint32_t ip;

			printf("CALL name: [%s], cr3: [0x%lx] pid: [%d], %s(",
					call->process_name,
					call->cr3,
					call->pid,
					"CONNECT");
			domain_read_current(parameter_values[6] + 0x14, 
					&port, sizeof(uint16_t));
			domain_read_current(parameter_values[6] + 0x16,
					&ip, sizeof(uint32_t));

			ip = ntohl(ip);
			port = ntohs(port);

			printf("ip: %hu.%hu.%hu.%hu, port: %hu)\n",
					(short)((ip >> 24) & 0xFF),
					(short)((ip >> 16) & 0xFF),
					(short)((ip >> 8) & 0xFF),
					(short)(ip & 0xFF), 
					port);


		}
		else if (parameter_values[5] == 0x1201f)
		{
			printf("CALL name: [%s], cr3: [0x%lx] pid: [%d], %s(",
					call->process_name,
					call->cr3,
					call->pid,
					"SEND");
			printf(")\n");
		}
		else if (parameter_values[5] == 0x12017)
		{
			printf("CALL name: [%s], cr3: [0x%lx] pid: [%d], %s(",
					call->process_name,
					call->cr3,
					call->pid,
					"RECV");
			printf(")\n");
		}
	}

	process_generic_syscall(call, parameter_values);
}

void process_NtRequestWaitReplyPort(struct syscall_info *call, uint32_t *parameter_values)
{
	struct port_message {
		uint16_t data_length;
		uint16_t length;
		uint16_t message_type;
		uint16_t virtual_range_offset;
		uint32_t client_id;
		uint32_t message_id;
		uint32_t callback_id;
		char data[328];
	} __attribute__ ((packed));



	struct port_message message;

	unsigned long final_address = parameter_values[1];

	domain_read_current(final_address, &message, sizeof(struct port_message));

	
	/* 0x90241 = magic DNS client id */

	uint16_t length = 0;
	uint32_t magic = 0;
	/* read magic dword */
	domain_read_current(final_address+20+8, &magic, sizeof(uint32_t));
	if(magic == 0x90241)
	{

		domain_read_current(final_address+20+0x34, &length, sizeof(uint16_t));

		char* dns_name =
			convert_unicode_string(length, final_address+20+0x38);

		if(dns_name != NULL)
		{
			printf("CALL name: [%s], cr3: [0x%lx] pid: [%d], %s(",
					call->process_name,
					call->cr3,
					call->pid,
					"DNS_LOOKUP");
			base16_print(dns_name);
			printf(")\n");
			free(dns_name);
		}
	}

	process_generic_syscall(call, parameter_values);

}

/* prints a windows NT syscall name and arguments given
 * a libxc handle and a syscall_info structure
 * for the system call
 */ 
void nt_print_syscall(int xc_iface, int domid, struct syscall_info* call)
{
	/*uint32_t stack_ptr = 0;*/

	/*uint32_t eprocess_ptr = 0;*/
	/*uint32_t ethread_ptr = 0;*/
	uint32_t *params = NULL;
	int got_params = 0;


	if(call->notification_type == SYSCALL_CALL)
	{

		if(nt_syscalls[call->number]->parameter_count != 0)
		{
			params = (uint32_t*)malloc(sizeof(uint32_t)*nt_syscalls[call->number]->parameter_count);

			if(params == NULL)
			{
				printf("COULD NOT ALLOCATE MEMORY\n");
				return;
			}
			got_params = domain_read_current(call->registers.edx + 8, params, 
					nt_syscalls[call->number]->parameter_count * 4);
			sp_save_parameters(params, call);
		}
	}
	else
	{
		struct saved_parameters *sp = NULL;


		sp = sp_find_and_remove_parameters(call->pid, call->tid, call->number);
		if(sp != NULL)
		{
			params = sp->parameters;
			free(sp);
		}

	}

	/* per-syscall processing */
	if(nt_syscalls[call->number]->handler == NULL)
	{
		process_generic_syscall(call, params);
	}
	else
	{
		syscall_handler_func call_handler = nt_syscalls[call->number]->handler; 
		(*call_handler)(call, params);
	}

	if(call->notification_type == SYSCALL_RET)
	{
		/* only free parameter list
		 * on syscall return 
		 */
		free(params);
	}

}
