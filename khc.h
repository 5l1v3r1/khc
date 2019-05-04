#ifndef _KHC_H_
#define _KHC_H_

#define MAX_HASH 16*1024
#define SALT_SIZE 256

void info(const char *fmt,...);
void fatal(const char *fmt,...);

struct entry_s
{
	char hash[MAX_HASH+1];
	char hash2[MAX_HASH+1];
	char salt[SALT_SIZE+1];
	char key[MAX_HASH+1];
	char unhashed[256];
	struct entry_s *link;
};

typedef struct entry_s entry;

entry *new_entry()
{
	return (entry *)calloc(1,sizeof(entry));
}

entry *insert(entry *p,char *salt,char *hash,char *key,char *hash2)
{
	entry *temp;
	if(p==NULL)
	{
		p=new_entry();
		if(p==NULL)
		{
			printf("Error\n");
			exit(0);
		}
		strncpy(p->salt,(char *)salt,SALT_SIZE);
		strncpy(p->hash,hash,MAX_HASH);
		strncpy(p->hash2,hash2,MAX_HASH);
		strncpy(p->key,key,MAX_HASH);
		strncpy(p->unhashed,"",255);
		p->link = p;
	}
	else
	{
		temp = p;
		while(temp->link != p)
			temp = temp->link;

		temp->link = new_entry(); 
		if(temp->link == NULL)
		{
			printf("Error\n");
			exit(0);
		}
		temp = temp->link;
		strncpy(temp->salt,salt,SALT_SIZE);
		strncpy(temp->hash,hash,MAX_HASH);
		strncpy(temp->hash2,hash2,MAX_HASH);
		strncpy(temp->key,key,MAX_HASH);
		strncpy(temp->unhashed,"",255);
		temp->link = p;
	}
	return (p);
}

void
print_entries( entry *p )
{
	entry *temp;
	temp = p;
	if(p!=NULL)
	{
		do
		{
			printf("hash:%s\nunhash:%s\n",temp->hash,temp->unhashed);
			temp=temp->link;
		} while(temp!=p);
	}
}

#endif
