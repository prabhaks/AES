hw6: aes.o hw6.o
	gcc -o hw6 -g aes.o hw6.o -L/home/scf-22/csci551b/openssl/lib -lcrypto -lm
		
aes.o: aes.c
	gcc -g -c -Wall aes.c -I/home/scf-22/csci551b/openssl/include
	
hw6.o: hw6.c hw6.h
	gcc -g -c -Wall hw6.c
	
clean:
	 rm -f *.o *.gch hw6
