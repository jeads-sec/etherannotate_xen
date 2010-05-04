#include "syscalls.h"
#include "hashtable.h"
#include <stdlib.h>
#include <xen/hvm/ether.h>
#include <memory.h>
#include <stdio.h>


struct hashtable *sp_table;
struct saved_parameters *sp_list_head;


struct hashtable *sp_init(void)
{
	struct hashtable *table = NULL;

	table = create_hashtable(SP_TABLE_ENTRIES, 
				sp_hash_fn,
				sp_equality_fn);
	sp_table = table;
	sp_list_head = NULL;

	return sp_table;
}

void sp_cleanup(void)
{
	struct saved_parameters *p = sp_list_head, *nextp;

	hashtable_destroy(sp_table, 0);

	
	while(p != NULL)
	{
		if(p->parameters != NULL)
			free(p->parameters);
			p->parameters = NULL;

		nextp = p->next;
		free(p);

		p = nextp;
	}
	

}

int sp_save_parameters(uint32_t *parameters, struct syscall_info *call_info)
{
	struct saved_parameters *sp = 
		malloc(sizeof(struct saved_parameters));

	char *hash_key = (char*)malloc(SP_KEY_SIZE);



	if(sp == NULL || hash_key == NULL)
	{
		if(sp != NULL)
			free(sp);

		if(hash_key != NULL)
			free(hash_key);

		return -1;
	}

	memset(sp, 0, sizeof(struct saved_parameters));
	memset(hash_key, 0, SP_KEY_SIZE);


	sp_create_hash_key(call_info->pid, call_info->tid, 
			call_info->number, 
			hash_key);

	sp->parameters = parameters;
	sp->timestamp = time(NULL);
	sp->pid = call_info->pid;
	sp->tid = call_info->tid;
	sp->call_number = call_info->number;
	
	if(sp_list_head == NULL)
	{
		sp_list_head = sp;
	}
	else
	{
		sp->next = sp_list_head;
		sp->prev = NULL;

		sp_list_head->prev = sp;
		sp_list_head = sp;
	}

	hashtable_insert(sp_table, 
			hash_key,
			sp);

	return 1;

}


struct saved_parameters *sp_find_parameters(uint32_t pid, uint32_t tid, uint32_t call_number)
{
	struct saved_parameters *result = NULL;
	char *hash_key = (char*)malloc(SP_KEY_SIZE);

	if(hash_key == NULL)
	{
		return NULL;
	}

	sp_create_hash_key(pid, tid, call_number, 
			hash_key);

	result = (struct saved_parameters *)
		hashtable_search(sp_table,
				hash_key);

	free(hash_key);

	return result;
}

struct saved_parameters *sp_find_and_remove_parameters(uint32_t pid, 
		uint32_t tid, uint32_t call_number)
{
	struct saved_parameters *result = NULL;

	char *hash_key = (char*)malloc(SP_KEY_SIZE);

	if(hash_key == NULL)
	{
		return NULL;
	}

	sp_create_hash_key(pid, tid, call_number, 
			hash_key);

	result = (struct saved_parameters *)
		hashtable_remove(sp_table,
				hash_key);

	free(hash_key);

	if(result != NULL)
	{
		if(result->prev == NULL)
		{
			sp_list_head = result->next;
			if(result->next != NULL)
			{
				result->next->prev = NULL;
			}
		}
		else
		{
			result->prev->next = 
				result->next;
			
			if(result->next != NULL)
			{
				result->next->prev =
					result->prev;
			}
		}
	}


	return result;
}

int sp_equality_fn(void *sp1, void *sp2)
{
	char *c1 = (char *)sp1;
	char *c2 = (char *)sp2;
	int i = 0;

	for(i = 0; i < SP_KEY_SIZE; i++)
	{
		if(c1[i] != c2[i])
		{
			return 0;
		}
	}

	return 1;
}

int sp_create_hash_key(uint32_t pid, uint32_t tid, uint32_t call_number, char *key_dest)
{
	memset(key_dest, 0, SP_KEY_SIZE);
	memcpy(key_dest, &pid, sizeof(uint32_t));
	memcpy(key_dest+sizeof(uint32_t), &tid, sizeof(uint32_t));
	memcpy(key_dest+(sizeof(uint32_t)*2), &call_number, sizeof(uint32_t));

	return 1;
}


unsigned int sp_hash_fn(void *value)
{
	const char* s_value = (const char*)value;
	unsigned int hash = 0;
	int c; 
	int i;

	for(i = 0; i < (SP_KEY_SIZE) ; i++)
	{
		c = s_value[i];
		hash = c + (hash << 6) + (hash << 16) - hash;
	}

	return hash;
}
