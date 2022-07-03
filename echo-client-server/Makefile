all: echo-client echo-server

echo-client : tc.cpp
	g++ -o echo-client tc.cpp -pthread -std=c++11

echo-server: ts.cpp
	g++ -o echo-server ts.cpp -pthread -std=c++11

clean:
	rm -f echo-client echo-server *.o