#include <stdio.h>
#include <stdlib.h>

char cmd[] = "/bin/sh";
int global_number = 0;

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
	printf("please input your name\n");
	read(0, buf, 0x10);
	printf(buf);
	if(global_number == 0x28){
		target();	
	}
	else{
		printf("try to find the door");
	}
}

int main(){	
	init();
	vulnfunc();
}
