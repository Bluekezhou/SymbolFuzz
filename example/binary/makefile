CFLAGS := -g -m32 -no-pie

simple_test: simple_test.c
	gcc -o simple_test simple_test.c ${CFLAGS} 

atoi: atoi.c
	gcc -o atoi atoi.c ${CFLAGS} 

printf: printf.c
	gcc -o printf printf.c ${CFLAGS} 

strlen: strlen.c
	gcc -o strlen strlen.c ${CFLAGS}

all: atoi printf strlen simple_test
	echo "finshed"

clean: 
	rm simple_test
	rm atoi
	rm strlen
	rm printf
