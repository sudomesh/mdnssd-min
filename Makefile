

all: mdnssd


mdnssd: main.c
	gcc -o mdnssd main.c

clean:
	rm -f mdnssd