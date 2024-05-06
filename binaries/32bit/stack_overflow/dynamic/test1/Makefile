LDFLAGS = 
CFLAGS = -fno-stack-protector -z now -m32 -no-pie -z execstack
CC = gcc
FILE = dynamic_test1
all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILE).c -o $(FILE) 
clean:
	rm -rf $(FILE) $(FILE).o
