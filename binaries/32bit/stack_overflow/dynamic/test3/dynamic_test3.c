#include <stdio.h>
#include <stdlib.h>


void backdoor() {
	system("hello world");
}

void init() {
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 1, 0);
	setvbuf(stderr, 0, 1, 0);
}

void vulnfunc() {
	char buf[0x10];
	read(0,buf,0x100);
	return;
}

int main(){	
	init();
	vulnfunc();
}
