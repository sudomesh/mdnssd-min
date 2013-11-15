

all: mdnssd-min


mdnssd-min: mdnssd-min.o
	$(CC) $(LDFLAGS) -Wall -o mdnssd-min $^

%.o: %.c %.h
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -I. -o $@ $<

clean:
	rm -f mdnssd-min *.o
