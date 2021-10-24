

all: mdnssd-min


mdnssd-min: mdnssd-min.o
	$(CC) $(LDFLAGS) -Wall -s -o mdnssd-min $^

%.o: %.c %.h
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -Os -c -I. -o $@ $<

clean:
	rm -f mdnssd-min *.o
