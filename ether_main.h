#ifndef __SYSTRACE_H__
#define __SYSTRCE_H__

#define EAX 1
#define ECX 2
#define EDX 3
#define EBX 4
#define ESP 5
#define EBP 6
#define ESI 7
#define EDI 8

int ether_domctl_readguest(int xc_iface, int dom, 
		unsigned long va,
		unsigned char *buffer, int length);

struct current_domain_t {
	int xc_iface;
	int xc_event_iface;
	int domid;
};

extern struct current_domain_t current_domain;

#endif
