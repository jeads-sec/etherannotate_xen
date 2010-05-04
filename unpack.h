#ifndef __UNPACK_H__
#define __UNPACK_H__

#include "pe.h"
#include "hashtable.h"

#define SANE_NUMBER_OF_SECTIONS 10

void unpack_dump_memory(uint32_t base, uint32_t va, uint32_t size, const char* name);
void unpack_generate_image_name(int layer, unsigned long int rip, const char* application, char *name);
void unpack_generate_alloc_name(const char* application, int layer, uint32_t start_va, uint32_t size, char* name);
int32_t *is_possible_oep(struct hashtable *memhash, unsigned long va);
void add_oep(struct hashtable *memhash, unsigned long va, int size);

typedef struct mapped_pe_t {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_OPTIONAL_HEADER pOptHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_SECTION_HEADER pSectHeader;

} mapped_pe;

#endif
