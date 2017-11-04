
SRC = ./src
OBJ = ./obj
BIN = ./bin
LIB = /lib/security

all: pam_hmac.so test

pam_hmac.o: $(SRC)/pam_hmac.c obj
	gcc -fPIC -fno-stack-protector -c $(SRC)/pam_hmac.c -o $(OBJ)/pam_hmac.o

pam_hmac.so: pam_hmac.o obj bin
	sudo ld -x --shared -o $(BIN)/pam_hmac.so $(OBJ)/pam_hmac.o

test: $(SRC)/test.c bin
	g++ -o $(BIN)/test $(SRC)/test.c -lpam -lpam_misc

obj:
	mkdir -p $(OBJ)

bin:
	mkdir -p $(BIN)

clean:
	rm -rf $(OBJ) $(BIN)

install:
	cp $(BIN)/pam_hmac.so $(LIB)/pam_hmac.so
