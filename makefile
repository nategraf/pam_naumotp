
SRC = ./src
OBJ = ./obj
BIN = ./bin
LIB = /lib/security

all: mypam.so test

mypam.o: $(SRC)/mypam.c obj
	gcc -fPIC -fno-stack-protector -c $(SRC)/mypam.c -o $(OBJ)/mypam.o

mypam.so: mypam.o obj bin
	sudo ld -x --shared -o $(BIN)/mypam.so $(OBJ)/mypam.o

test: $(SRC)/test.c bin
	g++ -o $(BIN)/test $(SRC)/test.c -lpam -lpam_misc

obj:
	mkdir -p $(OBJ)

bin:
	mkdir -p $(BIN)

clean:
	rm -rf $(OBJ) $(BIN)

install:
	cp $(BIN)/mypam.so $(LIB)/mypam.so
