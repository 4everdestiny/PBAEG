#include <stdio.h>
#include <stdlib.h>

char cmd[] = "/bin/sh";

void init() {
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 1, 0);
	setvbuf(stderr, 0, 1, 0);
}

void target(){
	system("/bin/sh");
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
