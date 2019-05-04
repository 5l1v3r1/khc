#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <netinet/in.h>
#include <resolv.h>

#include "ip.h"
#include "khc.h"

//#define DEBUG
#define HASH_MAGIC "|1|"
#define HASH_DELIM '|'
#define MAX_HOST_LENGTH 255 /* As stated by RFC */
#define MAX_IP_STRING 40 /* 4*3 + 3 + \0 -> 16 for IPv4, no CIDR included
			    8*4 + 7 + \0 -> 40 for IPv6, no CIDR included
			    for CIDR-parsing the value needs to get raised */
#define MAX_FILENAME 256

u_int32_t hashes_found = 0;
char begin_ip[MAX_IP_STRING];
char end_ip[MAX_IP_STRING];
char identity_file[MAX_FILENAME+1];
char dict_file_name[MAX_FILENAME+1];
static char * hash_host(const char *, unsigned char *);
static void usage(const char *);
static void fout_info(const char *hostname,char *key);
static void break_known_host(entry *,const char *);
static void dict_attack(entry *);
static void attack_private_ips(entry *,bool);
static void break_ip(entry *,char *,char *, bool);
static int32_t extract_salt(const char *, u_int64_t ,unsigned char *,
	size_t,char *,size_t);
bool verbose = false;
bool guess_priv_nets = 0;

FILE *file=NULL;
entry * read_file(const char *,entry *);

static void usage(const char *name) 
{
    printf("%s -f FILE OPTIONS\n"
	    "\tOptions\n"
	    "\t -6\n"
	    "\t\t specifies the use of IPv6 addresses, IPv4 is used by default\n"
	    "\t\t any option can get used with IPv6 too if you use -6\n\n"
	    "\t -f file_name\n"
	    "\t\t specifies the known_host file\n\n"
	    "\tMutually exclusive options:\n"
	    "\t -F single_host name/single_ip_address\n"
	    "\t\t Check a single host name taken from stdin\n"
	    "\t\t You might use it in scripts if -w ain't worth the effort\n"
	    "\t -w dict_file\n"
	    "\t\t Check all hosts from a ASCII file, one host a line\n"
	    "\t\t This is useful to test host names or single IPs from a list\n"
	    "\t -p\n"
	    "\t\t Checks all private IP addresses in this order\n"
	    "\t\t IPv4: 192.168.x.x, 172.16-32.x.x, 10.x.x.x\n"
	    "\t\t IPv6: has to get added!\n"
	    "\t -s specifies the start address for a range\n"
	    "\t\t This can get used to work distributed on IP ranges\n"
	    "\t\t or check a limited range (for example just 192.168.x.x)\n"
	    "\t -e specifies the ending address for a range\n"
	    "\t\t This can get used to work distributed on IP ranges\n"
	    "\t\t or check a limited range (for example just 192.168.x.x)\n"
	    "\t -o file name\n"
	    "\t\t Save results to file\n"
	    "\t -v Print every check made\n"
	    ,name);
    exit(0);
}

    int32_t
main(int32_t argc, char **argv)
{
    char *rr_hostname = NULL;
    entry *file_entries = NULL;
    int32_t opt;
    bool is_ipv6 = false;

    while((opt = getopt(argc, argv,"6vw:F:f:s:e:po:")) != -1) {
	switch (opt) {
	    case 'F':
		if(strlen(optarg)<=MAX_HOST_LENGTH)
		    rr_hostname = optarg;
		else
		    fatal("Host name too long");
		break;
	    case 'f':
		if(strlen(optarg)>MAX_FILENAME)
		    fatal("Identity file name too long");
		else
		    strncpy(identity_file,optarg,MAX_FILENAME);
		break;
	    case 's':
		if(strlen(optarg)>MAX_IP_STRING)
		    fatal("value too long");
		else
		    strncpy(begin_ip, optarg, MAX_IP_STRING); 
		break;
	    case 'e':
		if(strlen(optarg)>MAX_IP_STRING)
		    fatal("value too long");
		else
		    strncpy(end_ip, optarg, MAX_IP_STRING);
		break;
	    case '6':
		is_ipv6 = true;
		break;
	    case 'p':
		guess_priv_nets = 1;
		break;
	    case 'w':
		if(strlen(optarg)>MAX_FILENAME)
		    fatal("dictionary file name too long");
		else
		    strncpy(dict_file_name,optarg,MAX_FILENAME);
		break;
	    case 'o':
		if(strlen(optarg)>MAX_FILENAME)
		    fatal("out file name too long");
		else {
		    file = fopen(optarg,"a");
		    if(!file) fatal("Couldn't open file: %s",optarg);
		}
		break;
	    case 'v':
		verbose = true;
		break;
	    default:
		usage(argv[0]);	
	}
    }

    if(strlen(dict_file_name)>0 && strlen(identity_file)>0 )
    {
	/* dictionary attack on hash */
	file_entries = read_file(identity_file,file_entries);
	dict_attack(file_entries);	
    }
    else if(rr_hostname != NULL && strlen(identity_file)>0 && !guess_priv_nets)
    {
	/*
	 * look for a particular host name to be hashed on the specified
	 * known_hosts file
	 */
	file_entries = read_file(identity_file,file_entries);
	break_known_host(file_entries,rr_hostname);
    }
    else if(rr_hostname == NULL && strlen(identity_file)>0 && strlen(begin_ip)>0 &&strlen(end_ip)>0)
    {
	/* Let's try a range of ip addresses */
	file_entries = read_file(identity_file,file_entries);
	break_ip(file_entries,begin_ip,end_ip,is_ipv6);
    }

    else if(rr_hostname == NULL && guess_priv_nets && strlen(identity_file)>0)
    {
	/* Let's try ipv4 private networks ranges */
	file_entries = read_file(identity_file,file_entries);
	attack_private_ips(file_entries,is_ipv6);
    }
    else
	usage(argv[0]);

    if(file)
    {
	entry *temp;
	temp = file_entries;
	if(file_entries!=NULL)
	{
	    do
	    {
		/* Report not cracked file entries */
		if(strlen(temp->unhashed)==0)
		    fout_info(temp->hash,temp->key);

		temp=temp->link;
	    } while(temp!=file_entries);
	}
	if(verbose) info("[i] Closing file");
	fclose(file);	
    }

    info("%d hashes found",hashes_found);
    return 0;
}

/*
 * Writes to file a pair host name and key
 * when -o command line flag is specified,
 * adds a '\n' too.
 */
    static void
fout_info(const char *hostname,char *key)
{
    if(file && hostname && key)
    {
	if(verbose) info("[i] Writing to file");
	fprintf(file,"%s %s\n",hostname,key);
    }
}

/*
 * This function reads a known_hosts file
 * and loads every hashed entry it finds
 * into a linked list.
 */
    entry *
read_file(const char *filename,entry *file_entries)
{
    if(verbose) info("[i] Reading file into memory: %s",filename);
    FILE *in = NULL;
    char *cp, *kp, *kp2;
    char line[16*1024];
    int32_t skip = 0, num = 0, invalid = 0;
    entry *r = file_entries;

    if((in = fopen(filename, "r")) == NULL)
	fatal("fopen: %s", strerror(errno));

    while(fgets(line, sizeof(line), in)) {
	if((cp = strchr(line, '\n')) == NULL) {
	    info("[!] line %d too long: %.40s...", num + 1, line);
	    skip = 1;
	    invalid = 1;
	    continue;
	}

	num++;
	if(skip) {
	    skip = 0;
	    continue;
	}
	*cp = '\0';

	/* Skip leading white-space, empty and comment lines. */
	for(cp = line; *cp == ' ' || *cp == '\t'; cp++)
	    ;
	if(!*cp || *cp == '\n' || *cp == '#')
	    continue;
	
	/* Find the end of the host name portion. */
	for(kp = cp; *kp && *kp != ' ' && *kp != '\t'; kp++)
	    ;
	if(*kp == '\0' || *(kp + 1) == '\0') {
	    info("[!] line %d missing key: %.40s...",
		    num, line);
	    invalid = 1;
	    continue;
	}
	*kp++ = '\0';
	kp2 = kp;

	if(*cp == HASH_DELIM) {
	    unsigned char salt[256]={0};
	    char hash[256]={0};

	    /* Extract salt from known host entry */
	    if(extract_salt(cp, strlen(cp), salt,
			sizeof(salt),hash,sizeof(hash)) == -1)
		info("[!] extract_salt");
	    else
		r = insert(r,(char *)salt,cp,kp,hash);
	}
	else
	{
	    info("[!] line: %d: not hashed "
		    "name: %.64s...",num,line);
	    fout_info(line,"Not hashed");
	}
    }
    fclose(in);

    if(invalid)
	fatal("%s is not a valid known_hosts file",filename);
    return r;
}

/*
 * Hash name and checks if it matches one of
 * the loaded ones from file
 */
    static void
break_known_host(entry *file,const char *name)
{
    if(file && name)
    {
	entry *current;
	char *cp2;
	int32_t c;
	current = file;
	if(file!=NULL)
	{
	    do
	    {
		if(strlen(current->unhashed)==0)
		{
		    cp2= hash_host(name,(unsigned char*)current->salt);

		    if(cp2 == NULL) {
			info("[!] %.64s invalid hashed "
				,current->hash);
			continue;
		    }
		    c =(strcmp(cp2,current->hash2)==0);
		    if(c) {
			hashes_found++;
			printf("found: %s %s\n",name,current->key);
			fout_info(name,current->key);
			strncpy(current->unhashed,name,255);
			break;
		    }
		    else
			if(verbose) info("%s",name);
		}
		current=current->link;
	    } while(current!=file);
	}
    }
}

/*
 * Calculates hash for host with specified salt
 */
    static char *
hash_host(const char *host, unsigned char *salt)
{
    const EVP_MD *md = EVP_sha1();
    HMAC_CTX mac_ctx;
    unsigned char result[256]={0};
    char uu_salt[512]={0}, uu_result[512]={0};
    static char encoded[1024]={0};
    uint32_t len={0};

    len = EVP_MD_size(md);

    HMAC_Init(&mac_ctx, salt, len, md);
    HMAC_Update(&mac_ctx, (const unsigned char *)host, strlen(host));
    HMAC_Final(&mac_ctx, result, NULL);
    HMAC_cleanup(&mac_ctx);

    if(__b64_ntop(salt, len, uu_salt, sizeof(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, sizeof(uu_result)) == -1)
	fatal("host_char: __b64_ntop failed");
    snprintf(encoded, sizeof(encoded), "%s",uu_result);
    return (encoded);
}

/*
 * Extract encoded salt from entry in known_hosts file
 */
    static int32_t
extract_salt(const char *s, uint64_t l, unsigned char *salt, size_t salt_len,char *hash,size_t hash_len)
{
    char *p, *b64salt;
    uint32_t b64len;
    int32_t ret;

    if(l < sizeof(HASH_MAGIC) - 1) {
	info("[!] extract_salt: string too short");
	return (-1);
    }
    if(strncmp(s, HASH_MAGIC, sizeof(HASH_MAGIC) - 1) != 0) {
	info("[!] extract_salt: invalid magic identifier");
	return (-1);
    }
    s += sizeof(HASH_MAGIC) - 1;
    l -= sizeof(HASH_MAGIC) - 1;
    if((p = memchr(s, HASH_DELIM, l)) == NULL) {
	info("[!] extract_salt: missing salt termination character");
	return (-1);
    }

    b64len = p - s;
    /* Sanity check */
    if(b64len == 0 || b64len > 1024) {
	info("[!] extract_salt: bad encoded salt length %u", b64len);
	return (-1);
    }
    b64salt = malloc(1 + b64len);

    if(b64salt == NULL)
	fatal("malloc: out of memory (allocating %lu bytes)",1+b64len);

    memcpy(b64salt, s, b64len);
    b64salt[b64len] = '\0';

    ret = __b64_pton(b64salt, salt, salt_len);
    if(b64salt == NULL)
	fatal("Trying to free already freed memory");
    
    free(b64salt);

    if(ret == -1) {
	info("[!] extract_salt: salt decode error");
	return (-1);
    }
    if(ret != SHA_DIGEST_LENGTH) {
	info("[!] extract_salt: expected salt len %d, got %d",
		SHA_DIGEST_LENGTH, ret);
	return (-1);
    }

    p++;
    info("[i] Reading hash %s",p);
    strncpy(hash,p,hash_len);

    return (0);
}

/*
 * Reads host names from file, hash them and
 * checks for matches against entries in
 * known_hosts file
 */
    static void
dict_attack(entry *file)
{
    FILE *in = NULL;
    char *cp;
    char host[8*1024]={0};
    double num = 0;

    if((in = fopen(dict_file_name, "r")) == NULL)
	fatal("fopen: %s", strerror(errno));
    while(fgets(host, sizeof(host), in)) {
	if((cp = strchr(host, '\n')) == NULL || strlen(host) > 255 ) {
	    info("[!] host name too long: %.40s...\n", host);
	    continue;
	}

	num++;
	*cp = '\0';

	/* Skip leading white-space and empty lines. */
	for(cp = host; *cp == ' ' || *cp == '\t'; cp++)
	    ;
	if(!*cp || *cp == '\n')
	    continue;
	break_known_host(file,host);
    }
    fclose(in);
}

    static void
attack_private_ips( entry *file,bool is_ipv6 )
{
    if(!is_ipv6)
    {
	break_ip(file,"192.168.0.1","192.168.255.254",false); 
	break_ip(file,"172.16.0.1","172.31.255.254",false); 
	break_ip(file,"10.0.0.1","10.255.255.254",false); 
    } else
	printf("No private IPv6 (logic) added yet! CRY and blame benkei! :D");
}

    static void
break_ip( entry *file, char *sa, char *ea, bool is_ipv6 )
{
#ifdef DEBUG
    info("%s:%d:break_ip(%s,%s,%d)",__FILE__,__LINE__,sa,ea,is_ipv6);
#endif

    uint32_t r; 
    char ip[MAX_IP_STRING];

    if(!is_ipv6)
    {
	ipv4_addr *start = new_ipv4();
	ipv4_addr *end = new_ipv4();
	ipv4_addr *next = new_ipv4();
	char2ipv4(sa,start);
	char2ipv4(ea,end);
	copy_ipv4(start,next);
	while((r=cmp_ipv4(end,next)) >=0)
	{
	    ipv42char(next,ip);

#ifdef DEBUG
	    printf("{%s}\n",ip);
#endif

	    break_known_host(file,ip);
	    if(r==0) break;
	    next_ipv4(next,next);
	}
    }
    else {
	ipv6_addr *start = new_ipv6();
	ipv6_addr *end = new_ipv6();
	ipv6_addr *next = new_ipv6();
	char2ipv6(sa,start);
	char2ipv6(ea,end);
	copy_ipv6(start,next);
	while((r=cmp_ipv6(end,next)) >=0)
	{
	    ipv62char(next,ip);

#ifdef DEBUG
	    printf("{%s}\n",ip);
#endif
	    break_known_host(file,ip);
	    if(r==0) break;
	    next_ipv6(next,next);
	}
    }
}

    void
info(const char *fmt,...)
{
    va_list args;
    va_start(args,fmt);
    char buff[128]={0};
    vsnprintf(buff,128,fmt,args);
    fprintf(stdout,"%s\n",buff);
    va_end(args);
}

    void
fatal(const char *fmt,...)
{
    va_list args;
    va_start(args,fmt);
    char buff[128]={0};
    vsnprintf(buff,128,fmt,args);
    fprintf(stderr,"%s\n",buff);
    va_end(args);
    exit(EXIT_FAILURE);
}
