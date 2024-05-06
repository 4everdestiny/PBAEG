LDFLAGS = 
CFLAGS = -fno-stack-protector -z now -m64 -no-pie -z execstack -static
CC = gcc
FILE = static_test1
all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILE).c -o $(FILE) 
clean:
	rm -rf $(FILE) $(FILE).o

