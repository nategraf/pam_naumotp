
SRC = ./src
BIN = ./bin
LIB = /lib/security

all: pam_hmac.so

pam_hmac.so: $(SRC)/pam_hmac.c bin
	gcc -fPIC -shared $(SRC)/pam_hmac.c -o $(BIN)/pam_hmac.so -lpam -lcrypto

bin:
	mkdir -p $(BIN)

lib:
	mkdir -p $(LIB)

clean:
	rm -rf $(BIN)

install: lib
	cp $(BIN)/pam_hmac.so $(LIB)/pam_hmac.so
