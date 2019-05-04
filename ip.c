#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>

#include "ip.h"

#define BUF_SIZE 128
#define MAX_IPV4 255
#define MAX_IPV6 0xffff
#define SEP_IPV6 ":"

ipv6_addr *
new_ipv6() {
	ipv6_addr* r = (ipv6_addr *)calloc(1,sizeof(ipv6_addr));
	if(r == NULL)
	{
	    fprintf(stderr,"%s:%d Not enought memory available",__FILE__,__LINE__);
	    exit(EXIT_FAILURE);
	}
	return r;
}

void
char2ipv6(char *s,ipv6_addr * addr)
{
	char *p;
	uint8_t i = 0;
	uint32_t value=0;
	for((p=strtok(s,SEP_IPV6));
			p;
			(p=strtok(NULL,SEP_IPV6)))
	{
		value = (uint32_t)strtoul(p,NULL,16);
		if(i > 7 || value > MAX_IPV6)
		{
		    fprintf(stderr,"%s is not a valid IPv6 address",s);	
		    exit(EXIT_FAILURE);
		}
		else
			addr->pieces[i++] = value;
	}
}

void
ipv62char(ipv6_addr *addr,char *dst)
{
	if(addr && dst)
	{
		snprintf(dst,BUF_SIZE,"%x:%x:%x:%x:%x:%x:%x:%x",
				addr->pieces[0],
				addr->pieces[1],
				addr->pieces[2],
				addr->pieces[3],
				addr->pieces[4],
				addr->pieces[5],
				addr->pieces[6],
				addr->pieces[7]
			);
	}
}

void
next_ipv6(ipv6_addr *addr,ipv6_addr *next)
{
	if(addr && next)
	{
		bool inc_next = false;
		uint16_t value={0};
		uint8_t i;
		for(i=7;i!=0;i--)
		{
			value = addr->pieces[i];
			if(inc_next || i==7)
			{
				if(value+1>MAX_IPV6)
				{
					value = 0;
					inc_next = true;
				}
				else
				{
					value++;
					inc_next = false;
				}
			}	
			next->pieces[i] = value;
		}
	}
}

void
copy_ipv6(ipv6_addr *src,ipv6_addr *target)
{
	if( src && target)
	{
		uint8_t i; 
		for(i=0;i<8;i++)
		{
			target->pieces[i] = src->pieces[i];
		}
	}
}

/*
 * Compares two IPv6 addresses a1 and a2
 * Returns
 *	 0 if they are equal
 *	 1 if a1 > a2
 *	-1 if a1 < a2
 */
int8_t
cmp_ipv6(ipv6_addr *a1,ipv6_addr *a2)
{
	int8_t r = 0;
	int32_t d = 0;
	if(a1 && a2)
	{
		uint8_t i;
		for(i=0;i<8;i++)
		{
			d = (uint16_t)(a1->pieces[i] - a2->pieces[i]);
			if(d<0)
			{
				r = -1;
				break;
			}
			else if(d>0)
			{
				r = 1;
				break;
			}
		}
	}
	return r;
}

void
print_ipv6(ipv6_addr *addr)
{
	if(addr)
	{
		char str[BUF_SIZE]={0};
		ipv62char(addr,str);
		printf("{%s}\n",str);
	}
}

ipv4_addr *
new_ipv4() {
	ipv4_addr *r = (ipv4_addr *)calloc(1,sizeof(ipv4_addr));
	if(r == NULL)
	{
	    fprintf(stderr,"%s:%d Not enought memory available",__FILE__,__LINE__);
	    exit(EXIT_FAILURE);
	}
	return r;
}

void
char2ipv4(char *s,ipv4_addr *addr)
{
	uint8_t i;
	if(s && addr)
	{
	    i = sscanf(s,"%hu.%hu.%hu.%hu",
		    &addr->octets[0],
		    &addr->octets[1],
		    &addr->octets[2],
		    &addr->octets[3]);
	    if(i!=4)
	    {
		fprintf(stderr,"%s is not a valid IPv4 address",s);
		exit(EXIT_FAILURE);
	    }
	    else
	    {
		for(i=0;i<4;i++)
		{
		    if(addr->octets[i]>MAX_IPV4)
		    {
			fprintf(stderr,"%s is not a valid IPv4 address",s);
			exit(EXIT_FAILURE);
		    }
		}
	    }
	}
}

void
ipv42char(ipv4_addr *addr,char *dst)
{
	if(addr && dst)
	{
		snprintf(dst,BUF_SIZE,"%d.%d.%d.%d",
				addr->octets[0],
				addr->octets[1],
				addr->octets[2],
				addr->octets[3]
			);
	}
}

void
next_ipv4(ipv4_addr *addr,ipv4_addr *next)
{
	if(addr && next)
	{
		bool inc_next = false;
		uint16_t value={0};
		int8_t i;
		for(i=3;i>=0;i--)
		{
			value = addr->octets[i];
			if(inc_next || i==3)
			{
				if(value+1>MAX_IPV4)
				{
					value = 0;
					inc_next = true;
				}
				else
				{
					value++;
					inc_next = false;
				}
			}	
			next->octets[i] = value;
		}
	}
}

void
copy_ipv4(ipv4_addr *src,ipv4_addr *target)
{
	if(src && target)
	{
		uint8_t i; 
		for(i=0;i<4;i++)
		{
			target->octets[i] = src->octets[i];
		}
	}
}

/*
 * Compares two IPv4 addresses a1 and a2
 * Returns
 *	 0 if they are equal
 *	 1 if a1 > a2
 *	-1 if a1 < a2
 */
int8_t
cmp_ipv4(ipv4_addr *a1,ipv4_addr *a2)
{
	int8_t r = 0;
	int16_t d = 0;
	if(a1 && a2)
	{
		uint8_t i;
		for(i=0;i<4;i++)
		{
			d = a1->octets[i] - a2->octets[i];
			if(d<0)
			{
				r = -1;
				break;
			}
			else if(d>0)
			{
				r = 1;
				break;
			}
		}
	}
	return r;
}

void
print_ipv4(ipv4_addr *addr)
{
	if(addr)
	{
		char str[BUF_SIZE]={0};
		ipv42char(addr,str);
		printf("{%s}\n",str);
	}
}
