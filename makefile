
SRC = ./src
BIN = ./bin
LIB = /lib/security

all: pam_naumotp.so

pam_naumotp.so: $(SRC)/pam_naumotp.c bin
	gcc -fPIC -shared $(SRC)/pam_naumotp.c -o $(BIN)/pam_naumotp.so -lpam -lcrypto

bin:
	mkdir -p $(BIN)

lib:
	mkdir -p $(LIB)

clean:
	rm -rf $(BIN)

install: lib
	cp $(BIN)/pam_naumotp.so $(LIB)/pam_naumotp.so
