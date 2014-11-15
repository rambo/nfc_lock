CC         = gcc
CFLAGS     = -g -Wall -std=gnu99
LDFLAGS    =

PROGRAM = mifare-desfire-access
PROGRAM_FILES = mifare-desfire-access.c

CFLAGS	+= -g $(shell pkg-config --cflags libfreefare)
LDFLAGS	+= -g
LIBS 	+= $(shell pkg-config --libs libfreefare) 

all: $(PROGRAM)

%: %.c 
	$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)
		    