
#include <stdio.h>
#include <stdlib.h>
#include <xenctrl.h> 
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <assert.h>
#include "ether_main.h"
#include "unpack.h"
#include "ether.h"
#include "pe.h"
#include "hashtable.h"

extern char exe_image[256];
int32_t value_1 = 1;

int is_printable(char *s, int size)
{
	int i;

	for (i = 0 ; i < size && s[i] != '\0' ; i++)
		if (!isprint(s[i]))
			return 0;

	return 1;
}

void add_oep(struct hashtable *memhash, unsigned long va, int size)
{
	// Be sure to free this memory
	char *var = malloc(16);
	int32_t *val = NULL;
	int i = 0;

	assert(memhash);
	
	snprintf(var, 16, "%8.8lx", va);
	
	if ( (val = hashtable_search(memhash, var)) == NULL)
	{

		//printf("Adding %s %d\n", var, size);
		for (i = 0 ; i < (size <= 0 ? 1 : size) ; i++)
        {
	        snprintf(var, 16, "%8.8lx", va + i);
			hashtable_insert(memhash, var, &value_1);
	        var = malloc(16);
        }
        free(var);
	}
	else
	{
		// Update val
		*val = *val + 1;
	}

}

int32_t * is_possible_oep(struct hashtable *memhash, unsigned long va)
{
	char addr[16];
	int32_t *val = NULL;
	//char dump_name[256] = {0};
	
	assert(memhash);
	
	snprintf(addr, 16, "%8.8lx", va);

	val = hashtable_search(memhash, addr);

	return val;
}

int parse_pe(unsigned char *image, mapped_pe *pe)
{
	assert(image != NULL);
	assert(pe != NULL);

       // Find the DOS header
	
	pe->pDosHeader = (PIMAGE_DOS_HEADER) image;

	if ( pe->pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
	{
		printf("Image is not a valid DOS file\n");
		return -1;
	}

	// Find the NT header

	pe->pNtHeader = (PIMAGE_NT_HEADERS) (image + pe->pDosHeader->e_lfanew);

	if (pe->pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Image has invalid NT signature\n");
		return -1;
	}

	if (pe->pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Dumped image has invalid NT signature\n");
		return -1;
	}

	// Find the optional header
	
	pe->pOptHeader = &(pe->pNtHeader->OptionalHeader);

	printf("Image entry point RVA %8.8x\n", pe->pOptHeader->AddressOfEntryPoint);

	pe->pFileHeader = (PIMAGE_FILE_HEADER) &(pe->pNtHeader->FileHeader);

	if (pe->pFileHeader == NULL)
	{
		printf("File header is null.\n");
		return -1;
	}

	// Find the section header

	pe->pSectHeader = (PIMAGE_SECTION_HEADER) ((unsigned long) pe->pNtHeader + sizeof(IMAGE_NT_HEADERS));
	
	return 0;
}

void unpack_fix_pe(const char *dumpedimage, const char *origname, uint32_t newoep)
{
	FILE *dimage = NULL;
	FILE *oimage = NULL;
	unsigned char *ddata = NULL;
	unsigned char *odata = NULL;
	struct stat dstat = {0}, ostat = {0};
	unsigned int i = 0;
	char fixedfile[255] = {0};
	int use_original_name = strlen(origname) > 0 ? 1 : 0; // If no origname is specified then we just ignore it
	mapped_pe ope = {0}, dpe = {0};

	dimage = fopen(dumpedimage, "r");

	if (use_original_name)
	{
		oimage = fopen(origname, "r");

		if (oimage == NULL)
		{
			perror("Could not open original image");
			return;
		}
	}

	if (dimage == NULL)
	{
		perror("Could not open dumped image");
		return;
	}

	if(stat(dumpedimage, &dstat))
	{
		perror("Could not stat dumped image");
		return;
	}

	if(use_original_name && stat(origname, &ostat))
	{
		perror("Could not stat original image");
		return;
	}

	printf("Dumped image size: %u\n", (unsigned int) dstat.st_size);

	if (use_original_name)
		printf("Original Image size: %u\n", (unsigned int) ostat.st_size);

	ddata = (unsigned char *) malloc(dstat.st_size);

	if (ddata == NULL)
	{
		perror("Could not allocate dump image memory");
		return;
	}
	
	if (use_original_name)
	{
		odata = (unsigned char *) malloc(ostat.st_size);

		if(odata == NULL)
		{
			perror("Could not allocate original image memory");
			free(ddata);
			return;
		}
	}
	
	if (fread(ddata, dstat.st_size, 1, dimage) != 1)
	{
		perror("Error reading dumped image file");
		goto end; // I was tempted to #define throw goto
	}
	
	if (use_original_name && fread(odata, ostat.st_size, 1, oimage) != 1)
	{
		perror("Error reading original image file");
		goto end; // I figured that would be even uglier than this.
	}

	if (parse_pe(ddata, &dpe) )
	{
		printf("Could not parse dumped image\n");
		goto end; // I wish C had exceptions.
	}
	
	if (use_original_name && parse_pe(odata, &ope) )
	{
		printf("Could not parse original image\n");
		goto end; // I hope the velociraptors don't eat me.
	}

	// Fix the OEP on the dumped image

	if (newoep != 0)
	{
		dpe.pOptHeader->AddressOfEntryPoint = newoep;
		printf("Fixed dump image to have OEP of RVA %8.8x\n", dpe.pOptHeader->AddressOfEntryPoint);
	}

	// Fix the sections

	// If the exe_image is set, use it's number of sections
	if (use_original_name)
	{
		printf("Executable image defined, fixing the number of sections\n");
		dpe.pFileHeader->NumberOfSections = ope.pFileHeader->NumberOfSections;
	}
	
	// This is copied from OllyDump

	for (i = 0; i < (dpe.pFileHeader->NumberOfSections) ; i++)
	{
		// Validate the pointers
		if ( (unsigned long) &(dpe.pSectHeader[i]) > (unsigned long) (ddata + dstat.st_size) )
		{
			printf("Bad pointer in the section header %d\n", i);
			break;
		}

		// Check to see if it's printable to avoid filling the screen with junk
		if (is_printable((char *) dpe.pSectHeader[i].Name, IMAGE_SIZEOF_SHORT_NAME))
			printf("Section Name: %s\n", dpe.pSectHeader[i].Name);
		
		dpe.pSectHeader[i].SizeOfRawData = dpe.pSectHeader[i].Misc.VirtualSize;
		dpe.pSectHeader[i].PointerToRawData = dpe.pSectHeader[i].VirtualAddress;

	}

	// Dump the file
	snprintf(fixedfile, sizeof(fixedfile) - 1, "%s-fixed", dumpedimage);
	FILE *dumpout = fopen(fixedfile, "w");
	fwrite(ddata, dstat.st_size, 1, dumpout);
	fclose(dumpout);

 end:
	free(ddata);
	if (use_original_name)
		free(odata);
}

void unpack_dump_memory(uint32_t base, uint32_t va, uint32_t size, const char* name)
{

	unsigned char *image = 
		(unsigned char *)malloc(size);

	if(image != NULL)
	{
		char filename[256];
		
		FILE *f;

		memset(image, 0, size);
		ether_readguest(current_domain.xc_iface, 
				current_domain.domid,
				base,
				image,
				size);

		snprintf(filename, 255, "./images/%s.bin",
				name);

		filename[255] = 0;

		f = fopen(filename, "w");
		fwrite(image, sizeof(unsigned char), size, f);
		fclose(f);

		free(image);

		printf("Fixing %s\n", exe_image);
		unpack_fix_pe(filename, exe_image, va - base);

	}
}

void unpack_generate_image_name(int layer, unsigned long int rip, const char* application, char *name)
{
	snprintf(name, 255, "%s.image.l%8.8lx-%d", 
		 application,
		 rip,
		 layer);
	
}

void unpack_generate_alloc_name(const char* application, int layer, uint32_t start_va, uint32_t size, char* name)
{
 	snprintf(name, 255, "%s.alloc.l%d.0x%08x-0x%08x",
			application,
	 		layer,
			start_va,
			start_va + size);
}


