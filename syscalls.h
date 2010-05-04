#ifndef _SYSCALLS_H_
#define _SYSCALLS_H_

#include "hashtable.h"
#include <time.h>
/* for xen's uint32_t */
#include <xenctrl.h>
struct syscall_info;

struct saved_parameters {
	uint32_t *parameters;
	int parameter_count;

	time_t timestamp;

	uint32_t pid;
	uint32_t tid;
	uint32_t call_number;

	/* used to keep track of structures
	 * to free them on exit
	 * and for garbage collecting
	 */
	struct saved_parameters *next;
	struct saved_parameters *prev;
};

#define NT_SYSCALL_COUNT 284 
#define MAX_PARAM_COUNT 16

#define SP_TABLE_ENTRIES 1024
#define SP_KEY_SIZE (sizeof(uint32_t)*3)

extern struct nt_syscall_info* nt_syscalls[NT_SYSCALL_COUNT];
extern struct hashtable *nt_syscall_table;
extern struct hashtable *sp_table;

typedef void(*syscall_handler_func)(struct syscall_info *, uint32_t *);

unsigned int hash_fn(void *value);
int string_equality_fn(void *s1, void *s2);

void nt_parse_parameters(void); 
int nt_populate_syscalls(void);
void nt_free_syscalls(void);
void nt_print_syscall(int xc_iface, int domid, struct syscall_info* call);

void sp_cleanup(void);
struct hashtable *sp_init(void);

int sp_save_parameters(uint32_t *parameters, struct syscall_info *call_info);
struct saved_parameters *sp_find_parameters(uint32_t pid, uint32_t tid, uint32_t call_number);
struct saved_parameters *sp_find_and_remove_parameters(uint32_t pid, 
		uint32_t tid, uint32_t call_number);

int sp_equality_fn(void *sp1, void *sp2);
int sp_create_hash_key(uint32_t pid, uint32_t tid, uint32_t call_number, char *key_dest);
unsigned int sp_hash_fn(void *value);

int domain_read_current(unsigned long va, void *dest, int length);

struct parameter_type {
	char *type;
	int indirection;
};

/* a structure to hold some basic information about a windows nt 
 * system call. This will later be expanded with parameter
 * type information
 *
 * This describes information about the system call in
 * general, not a particular instance of that call. 
 */
struct nt_syscall_info 
{
	char *name;
	int number;
	int parameter_count;
	struct parameter_type params[MAX_PARAM_COUNT];
	syscall_handler_func handler;
};

void process_NtDeviceIoControlFile(struct syscall_info *call, uint32_t *parameter_values);
void process_NtRequestWaitReplyPort(struct syscall_info *call, uint32_t *parameter_values);

#endif
