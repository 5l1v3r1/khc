PROG=khc
CC=gcc
CFLAGS=-pipe -O2 -Wall -std=c99 -pedantic
SRCS=khc.c ip.c
OBJS=khc.o ip.o

$(PROG): $(OBJS)
	$(CC) -lcrypto -lm -o $(PROG) $(OBJS)
$(OBJS): $(SRCS)
	$(CC) -c $(CFLAGS) $(<) -o $(@)
clean:
	rm $(OBJS) $(PROG) 
