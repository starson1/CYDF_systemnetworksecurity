#Makefile

main: main.o
	g++ -o airodump main.o -lpcap

main.o : main.cpp

clean : 
	rm -f main
	rm -f *.o

