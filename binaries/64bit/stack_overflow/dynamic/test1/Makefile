LDFLAGS = 
CFLAGS =  -fno-stack-protector -O2 -D_FORTIFY_SOURCE=2 -z now -m64 -no-pie -z execstack
CC = gcc
FILE = dynamic_test1
all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILE).c -o $(FILE) 
clean:
	rm -rf $(FILE) $(FILE).o
