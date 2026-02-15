remake:
	rm -f Server Client
	gcc server.c -lcrypto -o Server
	gcc client.c -lcrypto -o Client