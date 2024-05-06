LDFLAGS = 
CFLAGS = -fstack-protector-all -z now -m64 -no-pie -z noexecstack
CC = gcc
FILE = fmt_stack_canary
all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILE).c -o $(FILE) 
clean:
	rm -rf $(FILE) $(FILE).o

