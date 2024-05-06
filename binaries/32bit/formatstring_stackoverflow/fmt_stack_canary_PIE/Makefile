LDFLAGS = 
CFLAGS = -fstack-protector-all -z now -m32 -fpie -pie -z noexecstack
CC = gcc
FILE = fmt_stack_canary_PIE
all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILE).c -o $(FILE) 
clean:
	rm -rf $(FILE) $(FILE).o
