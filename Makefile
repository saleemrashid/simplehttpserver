CC     := clang
CFLAGS := -std=c11 -pedantic -g -O3 -Wall -Wextra -Werror -pthread

EXENAME := simplehttpserver

all: $(EXENAME)

$(EXENAME): simplehttpserver.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(EXENAME)
