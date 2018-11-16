x86: libhook.c
	gcc -o libhook_x86.so libhook.c -m32 -pie -fpie -fno-pic

x64: libhook.c
	gcc -o libhook_x64.so libhook.c -pie -fpie -fno-pic 
:q

all: x86 x64
	echo "finished"

clean:
	rm libhook_*.so
