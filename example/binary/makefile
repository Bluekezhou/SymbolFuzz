CFLAGS := -g -m32 -no-pie

simple_test: simple_test.c
	gcc -o simple_test simple_test.c ${CFLAGS} 

atoi: atoi.c atoi_2.c atoi_3.c
	gcc -o atoi atoi.c ${CFLAGS} 
	gcc -o atoi2 atoi_2.c ${CFLAGS}
	gcc -o atoi3 atoi_3.c ${CFLAGS}

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
