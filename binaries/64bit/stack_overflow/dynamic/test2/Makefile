LDFLAGS = 
CFLAGS = -fno-stack-protector -z now -m64 -no-pie -z noexecstack
CC = gcc
FILE = dynamic_test2
all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILE).c -o $(FILE) 
clean:
	rm -rf $(FILE) $(FILE).o
