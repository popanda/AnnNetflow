ARCHIVE = xpopko00

CC = g++
CFLAGS = -O2 -std=c++11 -Wall -Wextra -pedantic
OBJ = 
LIB = -libpcap 


Netflow: main.o $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) main.o -o Netflow ${LIB} && sudo apt-get install libpcap-dev

main.o: main.cpp 
	$(CC) $(CFLAGS) -c main.cpp

pack: clean
	zip -r -9 $(ARCHIVE).zip *

clean:
	rm Netflow
	rm *.o
