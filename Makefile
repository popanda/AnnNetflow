ARCHIVE = xpopko00

CC = g++
CFLAGS = -O2 -std=c++11 -Wall -Wextra -pedantic 
OBJ = 


isa_exporter: isa_exporter.o $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) isa_exporter.o -o isa_exporter -lpcap

isa_exporter.o: isa_exporter.cpp 
	$(CC) $(CFLAGS) -c isa_exporter.cpp

pack: clean
	zip -r -9 $(ARCHIVE).zip *

clean:
	rm isa_exporter
	rm *.o
