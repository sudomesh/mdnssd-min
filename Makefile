

all: mdnssd-min


mdnssd-min: mdnssd-min.c mdnssd-min.h
	gcc -Wall -o mdnssd-min mdnssd-min.c

clean:
	rm -f mdnssd-min
