

all: mdnssd


mdnssd: main.c
	gcc -Wall -o mdnssd main.c

clean:
	rm -f mdnssd