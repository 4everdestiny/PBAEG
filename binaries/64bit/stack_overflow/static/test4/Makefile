LDFLAGS = 
CFLAGS = -fno-stack-protector -z now -m64 -no-pie -z noexecstack -static
CC = gcc
FILE = static_test4
all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILE).c -o $(FILE) 
clean:
	rm -rf $(FILE) $(FILE).o


