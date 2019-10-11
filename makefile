all: clean botnet
botnet:
	g++ -Wall -pthread -std=c++11 client.cpp -o client
	g++ -Wall -pthread -std=c++11 vgroup96.cpp -o tsamvgroup96
clean:
	rm -f client
	rm -f tsamvgroup96
run:
	./tsamvgroup96 4096
