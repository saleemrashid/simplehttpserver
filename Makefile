CC     := clang
CFLAGS := -std=c11 -pedantic -g -O3 -Wall -Wextra -Werror

EXENAME := simplehttpserver

all: $(EXENAME)

$(EXENAME): simplehttpserver.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(EXENAME)
