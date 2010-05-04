#include <stdlib.h>
#include <string.h> 
#include <errno.h>
#include <stdio.h>
#include <xenctrl.h> 
#include <xen/arch-x86/xen.h>
#include <xen/domctl.h>
#include <xen/hvm/ether.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <libdis.h>
#include <inttypes.h>
#include <signal.h>
#include "ether_main.h"
#include "ether.h"
#include "syscalls.h"
#include "unpack.h"
#include "hashtable.h"


int stop_loop = 0;
struct current_domain_t current_domain;
volatile void* shared_page;
volatile uint32_t *entries;
uint32_t service;
int event_port;
int unpack_layer = 0;
char exe_image[255];

int unpack_mode = 0;

unsigned long target_base = 0,
		      target_size = 0;

void termination(int where);

#define TERM_NORMAL 0
#define TERM_POST_BIND 1
#define TERM_POST_MMAP 2
#define TERM_POST_ERROR_EXIT 3
#define UNPACK_HYPERVISOR 0
#define UNPACK_USERSPACE 1

#define MEM_MAXSTRLEN 32  //maximum size of strings

/* use the disasm library to disassemble incoming instructions */
void disasm_init(void)
{
	x86_init(opt_none, NULL, NULL);
}

void disasm_instruction(struct instruction_info *instr_info)/*unsigned char *intr_data, unsigned long rip,
		unsigned long cr3) */
{
   unsigned char *intr_data = instr_info->instruction;
   unsigned long rip = instr_info->guest_rip;
   unsigned long cr3 = instr_info->cr3;
   
	char instr_string[80] = {0};
	int size = 0;
	unsigned int iter = 0, str_iter = 0;
	x86_insn_t insn;
	x86_reg_t* regis = NULL;
	x86_op_t *op;
	uint32_t reg_val = 0;
	char *ptr_val;
   vcpu_guest_context_t *ctxt = (vcpu_guest_context_t*)malloc(sizeof(vcpu_guest_context_t));
   char mem_str[MAX_OP_STRING];
   
	/*
	 * x86_insn_t->operands[i].op
	 * operands* = x86_operand_list = x86_oplist_t
	 * op = x86_op_t
	 * op.type, .datatype (size), .access, .flags
	 */

	memset(&insn, 0, sizeof(x86_insn_t));
	memset(ctxt, 0, sizeof(vcpu_guest_context_t));

	size = x86_disasm(intr_data, 15, rip, 0, &insn);

	if(size)
	{
		x86_format_insn(&insn, instr_string,
				80, intel_syntax);
		printf("%lx: %-30s   # ", rip, instr_string);
		//printf("operand_count: %d\n", insn.explicit_count);
		
      
      /* Try VCPU method */
      /* see /tools/libxc/xen/arch_x86/ files for ctxt contents */
      /*if(xc_vcpu_getcontext(current_domain.xc_iface, 
         current_domain.domid, 0, ctxt) != 0) //TODO!!! The register values are already stored in the instruction_info struct, this means we don't need a getcontext call!
      {
         printf("Could not read context from Xen domain!\n");
         return;   
	   }*/
	   
	   ptr_val = (char*)malloc(32);
		for(iter = 0; iter < insn.explicit_count; iter++)
		{
		   if(iter == 1)
		      op = &insn.operands->next->op;
		   else
		      op = &insn.operands[iter].op;
		      
		   //printf("operand %d type: 0x%x\n", iter, op->type);
		   //printf("operand %d data: 0x%x\n", iter, op->data);
		   
		   //Register Value
		   if(op->type == op_register)
		   {
		      regis = &op->data.reg;
		      switch(regis->id)
		      {
		         case EAX:
		            printf("%s: 0x%08x ", regis->name, instr_info->registers.eax);
		            reg_val = instr_info->registers.eax; //(uint32_t)ctxt->user_regs.eax;
		            break;
		         case EBX:
		            printf("%s: 0x%08x ", regis->name, instr_info->registers.ebx);
		            reg_val = instr_info->registers.ebx; //(uint32_t)ctxt->user_regs.ebx;
		            break;
		         case ECX:
		            printf("%s: 0x%08x ", regis->name, instr_info->registers.ecx);
		            reg_val = instr_info->registers.ecx; //(uint32_t)ctxt->user_regs.ecx;
		            break;
		         case EDX:
		            printf("%s: 0x%08x ", regis->name, instr_info->registers.edx);
		            reg_val = instr_info->registers.edx; //(uint32_t)ctxt->user_regs.edx;
		            break;
		         case ESP:
		            printf("%s: 0x%08x ", regis->name, instr_info->registers.esp);
		            reg_val = instr_info->registers.esp; //(uint32_t)ctxt->user_regs.esp;
		            break;
		         case EBP:
		            printf("%s: 0x%08x ", regis->name, instr_info->registers.ebp);
		            reg_val = instr_info->registers.ebp; //(uint32_t)ctxt->user_regs.ebp;
		            break;
		         case ESI:
		            printf("%s: 0x%08x ", regis->name, instr_info->registers.esi);
		            reg_val = instr_info->registers.esi; //(uint32_t)ctxt->user_regs.esi;
		            break;
		         case EDI:
		            printf("%s: 0x%08x ", regis->name, instr_info->registers.edi);
		            reg_val = instr_info->registers.edi; //(uint32_t)ctxt->user_regs.edi;
		            break;
		      }
		      /**
             * Memory maps a range within one domain to a local address range.  Mappings
             * should be unmapped with munmap and should follow the same rules as mmap
             * regarding page alignment.  Returns NULL on failure.
             *
             * @parm xc_handle a handle on an open hypervisor interface
             * @parm dom the domain to map memory from
             * @parm size the amount of memory to map (in multiples of page size)
             * @parm prot same flag as in mmap().
             * @parm mfn the frame address to map.
             */
		      /*ptr_val = xc_map_foreign_range(current_domain.xc_iface, 
		                  current_domain.domid, PAGE_SIZE, PROT_READ, reg_val);*/

            //domain_read_current(reg_val, ptr_val, MEM_MAXSTRLEN);
            /*ether_readguest(current_domain.xc_iface, current_domain.domid,
                  				reg_val, (unsigned char*)ptr_val, MEM_MAXSTRLEN);*/

            if(reg_val != 0 && domain_read_current(reg_val, ptr_val, MEM_MAXSTRLEN) != -1)
            {           
               //printf("ptr_val: 0x%x ", ptr_val);
               if(ptr_val != 0 && *ptr_val >= 0x20 && *ptr_val <= 0x7E)// && (char)(*ptr_val-1) == 0x00)
               {
                  printf("ptr_val[]: ");
                  for(str_iter = 0; str_iter < MEM_MAXSTRLEN; str_iter++)
                  {
                     if(ptr_val[str_iter] == 0)
                        break;
                     if(ptr_val[str_iter] >= 0x20 && ptr_val[str_iter] <= 0x7E)
                        printf("%c", ptr_val[str_iter]);
                  }
                  if(insn.explicit_count > 1 && iter != insn.explicit_count-1)
                     printf(", ");
                  //printf("*ptr_val: 0x%x ", *ptr_val);
               }
            }
            /*addr_val = xc_translate_foreign_address(current_domain.xc_iface, 
                          current_domain.domid, 0, reg_val);*/
            
		   }
		   //Memory Address
		   /*else if(x86_optype_is_memory(op->type))
		   {
		      get_operand_data_str(op, mem_str, sizeof(mem_str));
		      printf("get_operand_data_str: %s\n", mem_str);
		      printf("operand %d memory loc, size: 0x%x\n", 
		         iter, op->datatype, op->data);
		      if(op->datatype == op_dword)
		      {
		         printf("data: %d\n", op->data.dword);
		      }
		   }*/
		   
		}
		printf("\n");
		free(ptr_val);
		
		x86_oplist_free(&insn);
	}
	else
	{
		printf("%lx: %s\n", rip, "[invalid]");
	}
	
	free(ctxt);
	
}

void sigint_handler(int sig_number)
{
	static int been_here = 0;
	printf("Handling sigint\n");
	stop_loop = 1;

	if(been_here > 0)
		termination(TERM_NORMAL);

	been_here++;

}

void setup_signal_handler()
{

	struct sigaction sigint_action;

	sigint_action.sa_handler = sigint_handler;
	sigemptyset(&sigint_action.sa_mask);
	sigint_action.sa_flags = 0;

	sigaction(SIGINT, &sigint_action, NULL);
}

int main(int argc, char **argv)
{

	/* args = dom_id, new_eip
	*/

	unsigned long new_sysenter=0xDDDDD0AE;
	struct ether_communication comm;

	int false_pending_port;
	unsigned int memwrite_iter = 0;

	char filter_name[16];

	/*unsigned long target_base = 0,
		      target_size = 0;*/

	char dump_name[256];

	struct hashtable *memhash = NULL;
	
	memset(exe_image, 0, sizeof(exe_image));
	memset(dump_name, 0, sizeof(dump_name));

	nt_populate_syscalls();
	nt_parse_parameters();

	filter_name[0] = 0;

	if(argc >= 6 || argc <= 2)
	{
		fprintf(stderr, "Must have the arguments:\n"
				"\t\ttarget_domain_id systrace [target_process_name] [sysenter_eip]\n"
				"\t\ttarget_domain_id unpack_hypvervisor target_process_name [executable_image]\n"
				"\t\ttarget_domain_id unpack_userspace target_process_name [executable_image]\n"
				"\t\ttarget_domain_id instrtrace target_process_name\n"
				"\t\ttarget_domain_id memwrite target_process_name\n" 
				);
		termination(TERM_POST_ERROR_EXIT);
	}

	current_domain.xc_iface = xc_interface_open();
	current_domain.xc_event_iface = xc_evtchn_open();
	if(current_domain.xc_iface == 0)
	{
		fprintf(stderr, "Could not open interface to libxc\n");
	}
	if(current_domain.xc_event_iface == 0)
	{
		fprintf(stderr, "Could not open interface to libxc event channels\n");
	}

	current_domain.domid = atoi(argv[1]);
	if(strcmp(argv[2], "systrace") == 0)
	{
		service = ETHER_NOTIFY_SYSCALL;
	}
	else if(strcmp(argv[2], "instrtrace") == 0)
	{
		service = ETHER_NOTIFY_INSTRUCTION;
	}
	else if(strcmp(argv[2], "memwrite") == 0)
	{
		service = ETHER_NOTIFY_MEMWRITE;
	}
	else if(strcmp(argv[2], "unpack_hypervisor") == 0)
	{
		service = ETHER_NOTIFY_UNPACK;
        unpack_mode = UNPACK_HYPERVISOR;
	}
	else if(strcmp(argv[2], "unpack_userspace") == 0)
	{
		service = ETHER_NOTIFY_UNPACK;
        unpack_mode = UNPACK_USERSPACE;
	}
	else
	{
		fprintf(stderr, "Unknown argument for command parameter. Expected [systrace|unpack_hypervisor|unpack_userspace|instrtrace|memwrite], got: [%s]\n",
				argv[2]);
		termination(TERM_POST_ERROR_EXIT);
	}


	if(current_domain.xc_iface == -1)
	{
		perror("Failed to open xc interface");
		termination(TERM_POST_ERROR_EXIT);
	}

	if(current_domain.xc_event_iface == -1)
	{
		perror("Failed to open xc event interface");
		termination(TERM_POST_ERROR_EXIT);
	}


	if(ether_initialize_communication(current_domain.xc_iface, current_domain.domid, &comm) == -1)
	{
		perror("could not initialize communication with hypervisor");
	}

	printf("After init:\n");
	printf("\tshared_page_ptr: %p\n", comm.shared_page_ptr);
	printf("\tshared_page_mfn: 0x%lx\n", comm.shared_page_mfn);
	printf("\tdomid_source: %d\n", comm.domid_source);
	printf("\tevent_channel_port: %d\n", comm.event_channel_port);

	shared_page = xc_map_foreign_range(current_domain.xc_iface, DOMID_XEN, 
			getpagesize(), PROT_READ | PROT_WRITE,
			comm.shared_page_mfn);
	entries = (volatile uint32_t*)shared_page;

	if(shared_page == NULL)
	{
		perror("Could not map Xen memory to our process");
		termination(TERM_POST_ERROR_EXIT);
	}
	printf("Shared Page va: %p\n", shared_page);
	printf("Shared Page test:\n\t%s\n", (char*)shared_page);

	printf("Trying to bind to local port...\n");

	event_port = xc_evtchn_bind_interdomain(current_domain.xc_event_iface, 
			DOMID_SELF, comm.event_channel_port);

	/*event_port = comm.event_channel_port;*/

	if(event_port != -1)
	{
		printf("Success, bound to local port: %d\n",
				event_port);
	}
	else
	{
		perror("Could not bind xen port to local port");
		termination(TERM_POST_MMAP);
	}

	memset((void*)shared_page, 0, sizeof(uint32_t));

	printf("Trying to get first pending notification...\n");

	false_pending_port = xc_evtchn_pending(current_domain.xc_event_iface);

	if(false_pending_port == event_port)
	{
		printf("Taking off suprious pending notification...\n");
		if(xc_evtchn_unmask(current_domain.xc_event_iface, event_port) == -1)
		{
			perror("Could not unmask event port\n");
			termination(TERM_POST_BIND);
		}
	}
	else
	{
		printf("No pending notifications, good\n");
	}

	switch(service)
	{
		case ETHER_NOTIFY_SYSCALL:
			if (argc >= 5)
			{
				new_sysenter = strtoul(argv[4], NULL, 16);
			}
			if(argc >= 4)
			{
				if(strncmp("%", argv[3], 15) != 0)
				{
					strncpy(filter_name, argv[3], 15);
					filter_name[15] = 0;
					/* add a fake cr3 filter to avoid
					 * instantly tracing all system
					 * calls
					 */
					ether_add_cr3_filter(current_domain.xc_iface, current_domain.domid, 0);
				}
			} 
			break;
		case ETHER_NOTIFY_INSTRUCTION:
		case ETHER_NOTIFY_MEMWRITE:
		case ETHER_NOTIFY_UNPACK:
			if (argc == 5)
				strncpy(exe_image, argv[4], sizeof(exe_image) - 1);

			strncpy(filter_name, argv[3], 15);
			filter_name[15] = 0;
			break;
	}

	/*printf("Hit any key to setup trace...\n");*/
	/*getchar();*/

	disasm_init();

	switch(service)
	{
		case ETHER_NOTIFY_SYSCALL:
			if(ether_set_guest_sysenter(current_domain.xc_iface, current_domain.domid, new_sysenter) == -1)
			{
				perror("could not set sysenter on target");
				termination(TERM_POST_BIND);
			}
			break;

		case ETHER_NOTIFY_UNPACK:
		{
			int result;
			
            switch(unpack_mode)
            {
                case UNPACK_HYPERVISOR:
                    result = ether_unpack_notify(current_domain.xc_iface, current_domain.domid, 1);

                    if(result == -1)
                        termination(TERM_POST_BIND);
                    
                    result = ether_ss(current_domain.xc_iface, current_domain.domid, 
                            1);
                
                    if(result == -1)
                        termination(TERM_POST_BIND);

                    break;

                case UNPACK_USERSPACE:
                    // Enable both memory write and single-step instruction monitoring.
                    result = ether_memwrite_notify(current_domain.xc_iface, current_domain.domid, 
                            1);
                
                    if(result == -1)
                        termination(TERM_POST_BIND);

                    result = ether_ss(current_domain.xc_iface, current_domain.domid, 
                            1);
                
                    if(result == -1)
                        termination(TERM_POST_BIND);

                    result = ether_ss_notify(current_domain.xc_iface, current_domain.domid, 
                            1);

                    if(result == -1)
                        termination(TERM_POST_BIND);

                    // Create the memory hash table
                    memhash = create_hashtable(1024, hash_fn, string_equality_fn);
                    break;
            }

		}
		break;
		case ETHER_NOTIFY_MEMWRITE:
		{
			int result;
			result = ether_memwrite_notify(current_domain.xc_iface, current_domain.domid, 
					1);

			if(result == -1)
				termination(TERM_POST_BIND);

			result = ether_ss(current_domain.xc_iface, current_domain.domid, 1);

			if(result == -1)
				termination(TERM_POST_BIND);
		}
		break;
		case ETHER_NOTIFY_INSTRUCTION:
		{
			int result;
			result = ether_ss(current_domain.xc_iface, current_domain.domid, 
					1);
			if(result == -1)
				termination(TERM_POST_BIND);


			result = ether_ss_notify(current_domain.xc_iface, current_domain.domid, 
					1);

			if(result == -1)
				termination(TERM_POST_BIND);
		}
		break;
	}

	if(filter_name[0] != 0)
	{
		int result = -1;
		printf("Setting filter by name to: %s\n",
				filter_name);

		result = ether_name(current_domain.xc_iface, current_domain.domid, 
				XEN_DOMCTL_ETHER_ADD_NAME,
				filter_name);
		if(result == -1)
			termination(TERM_POST_BIND);
	}

	/* now starting event gather loop... */
	setup_signal_handler();
	while(!stop_loop)
	{

		// select didn't error, and returned, so we must have
		// a file descriptor to read from

		//printf("Getting pending event...\n");
		/*printf(".");*/
		int pending_port = xc_evtchn_pending(current_domain.xc_event_iface);
		/*printf("!");*/

		if(pending_port == event_port)
		{
			if(xc_evtchn_unmask(current_domain.xc_event_iface, event_port) == -1)
			{
				perror("Could not unmask event port in loop");
				break;
			}

			if((*entries))
			{
				uint32_t notify_type = *(entries+1);

				switch(notify_type)
				{
					case ETHER_NOTIFY_SYSCALL:
					{
						struct syscall_info *call_info =
							(struct syscall_info*)
							(shared_page+sizeof(uint32_t)+sizeof(uint32_t));



						if(notify_type == ETHER_NOTIFY_SYSCALL && call_info->number > 0 &&
								call_info->number < NT_SYSCALL_COUNT)
						{
							//printf(".");
							nt_print_syscall(current_domain.xc_iface,
									current_domain.domid, call_info);
						} 
					}
						break;
					case ETHER_NOTIFY_INSTRUCTION:	
					{
						/////////////////////////////////////////////////
						// see /xen/include/public/hvm/ether.h
						struct instruction_info *instr_info =
							(struct instruction_info*)
							(shared_page+sizeof(uint32_t)+sizeof(uint32_t));

						/*if(instr_info->guest_rip < 0x80000000UL)*/
						/*{*/
						/*printf("Instruction at rip 0x%lx, cr3: 0x%lx\n",*/
						/*instr_info->guest_rip,*/
						/*instr_info->cr3);*/
						/*}*/

						if(target_base != 0 &&
								instr_info->guest_rip < target_base + target_size &&
								instr_info->guest_rip > target_base)
						{
							/*printf("ESP: 0x%lx, ", instr_info->registers.rsp);*/
							//printf("Exec  %8.8lx\n", instr_info->guest_rip);
							if (service == ETHER_NOTIFY_UNPACK)
							{
								int32_t *val = NULL;

								if (( val = is_possible_oep(memhash, instr_info->guest_rip)) != NULL &&
									*val > 0)
								{
                                    printf("destroying memhash\n");
                                    fflush(stdout);
                                    hashtable_destroy(memhash, 0);
                                    printf("done destroying table\n");
                                    fflush(stdout);
                                    memhash = NULL;

                                    memhash = create_hashtable(1024, hash_fn, string_equality_fn);
									printf("Possible OEP %8.8lx\n", instr_info->guest_rip);
									*val *= -1;
									
									unpack_generate_image_name(unpack_layer++,
												   instr_info->guest_rip,
												   filter_name,
												   dump_name);
									
									unpack_dump_memory(target_base,
											   instr_info->guest_rip,
											   target_size,
											   dump_name);
								}

								
							}
							else
							{
								disasm_instruction(instr_info);/*instr_info->instruction,
										   instr_info->guest_rip,
										   instr_info->cr3);*/
							}
						}

					}
					break;
					case ETHER_NOTIFY_MEMWRITE:
					{
						struct memwrite_info *memwrite = 
							(struct memwrite_info*)
							(shared_page+sizeof(uint32_t)+sizeof(uint32_t));
						/* by default, only print
						 * memwrite executed by the
						 * process to the process
						 * address space
						 */
						int should_print = memwrite->va < target_base + target_size &&
								memwrite->va > target_base;
						should_print = should_print || (target_base != 0 &&
							memwrite->guest_rip < target_base + target_size &&
							memwrite->guest_rip > target_base);

						//printf("Write %8.8lx\n", memwrite->va);
						if (service == ETHER_NOTIFY_UNPACK)
						{
							// Check the executing address first
							/*if (is_possible_oep(memhash, memwrite->guest_rip))
							{
								printf("Possible OEP (MW) %8.8lx\n", memwrite->guest_rip);
								}*/

							// add the address
							add_oep(memhash, memwrite->va, memwrite->write_size);
	
						}
						else if(should_print)
						{
							printf("RIP: 0x%lx, VA: 0x%lx, size: %d, ",
									memwrite->guest_rip,
									memwrite->va, memwrite->write_size);
							if((int32_t)memwrite->write_size > 0)
                     {
							   printf("data: ");
							   for(memwrite_iter = 0; memwrite_iter < memwrite->write_size; 
						         memwrite_iter++)
							   {
							      printf("%02x ", memwrite->write_data[memwrite_iter]);
							   }
							   printf("\"");
							   for(memwrite_iter = 0; memwrite_iter < memwrite->write_size; 
						         memwrite_iter++)
							   {
							      //write printable ascii values
							      if(//memwrite->write_size == 1 && 
							         memwrite->write_data[memwrite_iter] <= 0x7E &&
							         memwrite->write_data[memwrite_iter] >= 0x20)
							      {
							         printf("%c", memwrite->write_data[memwrite_iter]);
							      }
							      else
							      {
							         printf(".");
							      }
							   }
							   printf("\"");
							   
							}
							printf("\n");
						}
					}
					break;
					case ETHER_NOTIFY_EXECUTION:
					{
						struct execution_info *execute = 
							(struct execution_info*)
							(shared_page+sizeof(uint32_t)+sizeof(uint32_t));

						printf("Execution of Target detected:\n");
						printf("\tImage Base:  0x%x\n", execute->image_base);
						printf("\tImage Size:  0x%x\n", execute->image_size);
						printf("\tEntry Point: 0x%x\n", execute->entry_point);
						target_base = execute->image_base;
						target_size = execute->image_size;

					}
					break;
					case ETHER_NOTIFY_UNPACK:
					{
						struct unpack_info *unpack = 
							(struct unpack_info*)
							(shared_page+sizeof(uint32_t)+sizeof(uint32_t));


						unpack_layer++;
						
						printf("Unpack-execution, layer: %d, va: 0x%x, layer start 0x%x, layer end 0x%x\n",
								unpack->layer,
								unpack->va,
								unpack->layer_start_va,
								unpack->layer_end_va);

						unpack_generate_image_name(unpack_layer, 
												   unpack->va,
												   filter_name,
												   dump_name);
						unpack_dump_memory(target_base, unpack->va, target_size, dump_name);

						if(unpack->va < target_base || unpack->va > target_base + target_size)
						{
							printf("va: 0x%x is out of range of image base 0x%x and 0x%x\n",
							       unpack->va,
							       unpack->layer_start_va,
							       unpack->layer_end_va);
							
							unpack_generate_alloc_name(filter_name, unpack_layer,
									unpack->layer_start_va,
									unpack->layer_end_va - unpack->layer_start_va,
									dump_name);
							unpack_dump_memory(unpack->layer_start_va,
									   unpack->va, 
									unpack->layer_end_va - unpack->layer_start_va,
									dump_name);
						}
						
					}
					break;
					default:
						printf("PROBLEM: Unknown notify type!\n");
				}

				(*entries) = 0;
				xc_domain_unpause(current_domain.xc_iface, current_domain.domid );
			}
			else
			{
				(*entries) = 0;
				xc_domain_unpause(current_domain.xc_iface, current_domain.domid );
			}

		}
		else
		{
			printf("Unknown event port pending: %d\n", pending_port);
			(*entries) = 0;
			xc_domain_unpause(current_domain.xc_iface, current_domain.domid );
		}

		
	}
	termination(TERM_NORMAL);
	return 0;
}

void termination(int where)
{
	switch(where)
	{
		case TERM_NORMAL:

			/* remove systemcall trapping */
			switch(service)
			{
				case ETHER_NOTIFY_SYSCALL:
					if(ether_set_guest_sysenter(current_domain.xc_iface, current_domain.domid, 0x00) == -1)
					{
						perror("could not remove sysenter hooks on target");
					}
					break;
				case ETHER_NOTIFY_MEMWRITE:
				case ETHER_NOTIFY_INSTRUCTION:
				case ETHER_NOTIFY_UNPACK:
					if(0 > ether_terminate(current_domain.xc_iface, current_domain.domid))
					{
						perror("could not stop single step tracing\n");
					}
			}

			xc_domain_unpause(current_domain.xc_iface, current_domain.domid );

		case TERM_POST_BIND:
			xc_evtchn_unbind(current_domain.xc_event_iface, event_port);
		case TERM_POST_MMAP:
			(*entries) = 0;
			munmap((void*)shared_page, getpagesize()); 
		case TERM_POST_ERROR_EXIT:
			/* clean up our mess */
			xc_evtchn_close(current_domain.xc_event_iface);
			xc_interface_close(current_domain.xc_iface);
			nt_free_syscalls();

			exit(0);

			/* prevent silly warnings */
			return;
	}

	return;
}
