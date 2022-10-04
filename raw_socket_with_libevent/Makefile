LIBS = -lstdc++
LIBEVENT = `pkg-config --libs libevent --cflags`
all: main.c
	$(CC) main.c -o a.out $(LIBS) $(LIBEVENT)
