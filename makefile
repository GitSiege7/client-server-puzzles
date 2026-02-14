remake:
	rm -f server client
	gcc server.c -lcrypto -o server
	gcc client.c -lcrypto -o client