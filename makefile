all: clean botnet
botnet:
	g++ -Wall -pthread -std=c++11 client.cpp -o client
	g++ -Wall -pthread -std=c++11 vgroup96.cpp -o vgroup96
clean:
	rm -f client
	rm -f vgroup96
run:
	sudo ./vgroup96 6969
