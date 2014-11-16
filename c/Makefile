CC         = gcc
CFLAGS     = -g -Wall -std=gnu99
LDFLAGS    =

#PROGRAM = mifare-desfire-access
#PROGRAM_FILES = mifare-desfire-access.c

#PROGRAM = cmac_example
#PROGRAM_FILES = cmac_example.c

PROGRAM = keydiversification_test
PROGRAM_FILES = keydiversification.c keydiversification_test.c

#PROGRAM = read_personalized
#PROGRAM_FILES = keydiversification.c read_personalized.c


CFLAGS	+= -g $(shell pkg-config --cflags libfreefare openssl)
LDFLAGS	+= -g
LIBS 	+= $(shell pkg-config --libs libfreefare openssl) 

all: $(PROGRAM)

%: %.c 
	$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)
		    
## Alternate way
## Set up basic variables:
##
#CC         = gcc
#CFLAGS     = -c -Wall -std=gnu99
#LDFLAGS    =
#
## List of sources:
#SOURCES    = mifare-desfire-access.c
#OBJECTS    = $(SOURCES:.c=.o)
#
## Name of executable target:
#EXECUTABLE = mifare-desfire-access 
#
#CFLAGS     += `pkg-config --cflags libfreefare`
#LDFLAGS    += `pkg-config --libs libfreefare`
#
#
#all: $(SOURCES) $(EXECUTABLE)
#	
#$(EXECUTABLE): $(OBJECTS)
#	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) 
#
#.c.o:
#	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
#
#clean:
#	rm $(OBJECTS) $(EXECUTABLE)
#
