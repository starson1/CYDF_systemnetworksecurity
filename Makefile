all: main

main: main.cpp
	g++ -o main main.cpp -lnetfilter_queue

clean:
	rm -f  main *.o