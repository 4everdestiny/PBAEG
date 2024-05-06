LDFLAGS = 
CFLAGS = -fstack-protector-all -m32 -no-pie -z noexecstack
CC = gcc
FILE = fmt_stack_canary
all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILE).c -o $(FILE) 
clean:
	rm -rf $(FILE) $(FILE).o
