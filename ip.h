#ifndef _IP_H_
#define _IP_H_

struct ipv6_addr_s {
	uint32_t pieces[8];
};

struct ipv4_addr_s {
	uint16_t octets[4];
};

typedef struct ipv6_addr_s ipv6_addr;
typedef struct ipv4_addr_s ipv4_addr;

/* ipv4 */
ipv4_addr* new_ipv4();
void char2ipv4(char *,ipv4_addr *);
void ipv42char(ipv4_addr *,char *);
void print_ipv4(ipv4_addr *);
void next_ipv4(ipv4_addr *,ipv4_addr *);
void copy_ipv4(ipv4_addr *,ipv4_addr *);
int8_t cmp_ipv4(ipv4_addr *,ipv4_addr *);

/* ipv6 */
ipv6_addr* new_ipv6();
void char2ipv6(char *,ipv6_addr *);
void ipv62char(ipv6_addr *,char *);
void print_ipv6(ipv6_addr *);
void next_ipv6(ipv6_addr *,ipv6_addr *);
void copy_ipv6(ipv6_addr *,ipv6_addr *);
int8_t cmp_ipv6(ipv6_addr *,ipv6_addr *);

#endif
