LDFLAGS = 
CFLAGS = -fstack-protector-all -z now -m64 -no-pie -z noexecstack
CC = gcc
FILE = printf_cond
all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILE).c -o $(FILE) 
clean:
	rm -rf $(FILE) $(FILE).o

