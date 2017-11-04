
SRC = ./src
OBJ = ./obj
BIN = ./bin
LIB = /lib/x86_64-linux-gnu/security/

all: pam_hmac.so

pam_hmac.o: $(SRC)/pam_hmac.c obj
	gcc -fPIC -c $(SRC)/pam_hmac.c -o $(OBJ)/pam_hmac.o -lcrypto

pam_hmac.so: pam_hmac.o obj bin
	ld -x --shared -o $(BIN)/pam_hmac.so $(OBJ)/pam_hmac.o

obj:
	mkdir -p $(OBJ)

bin:
	mkdir -p $(BIN)

lib:
	mkdir -p $(LIB)

clean:
	rm -rf $(OBJ) $(BIN)

install: lib
	cp $(BIN)/pam_hmac.so $(LIB)/pam_hmac.so
