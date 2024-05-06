#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void init() {
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 1, 0);
	setvbuf(stderr, 0, 1, 0);
}

void vulnfunc() {
	char buf[0x10];
	read(0,buf,0x10);
	if(strcmp(buf,"hello world") == 0){
	    puts("you find it!");
	}
	else{
	    puts("there is no magic");
	    exit(0);
	}
	read(0,buf,0x100);
	return;
}

int main(){	
	init();
	vulnfunc();
}
