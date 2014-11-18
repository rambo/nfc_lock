CC         = gcc
CFLAGS     = -g -Wall -std=gnu99
LDFLAGS    =
PROGRAMS   =

PROGRAMS += mifare-desfire-access
MIFARE_DESFIRE_ACCESS_SRC = mifare-desfire-access.c

#PROGRAM = cmac_example
#PROGRAM_FILES = cmac_example.c

PROGRAMS += keydiversification_test
KEYDIVERSIFICATION_TEST_SRC = keydiversification.c keydiversification_test.c

PROGRAMS += read_personalized
READ_PRESONALIZED_SRC = keydiversification.c read_personalized.c

#PROGRAM = pthread_example
#PROGRAM_FILES = pthread_example.c

CFLAGS_WITH_PTHREAD = $(CFLAGS) -pthread


CFLAGS	+= -g $(shell pkg-config --cflags libfreefare openssl)
LDFLAGS	+= -g
LIBS 	+= $(shell pkg-config --libs libfreefare openssl) 

all: $(PROGRAMS)

mifare-desfire-access: $(MIFARE_DESFIRE_ACCESS_SRC)
	$(CC) $(MIFARE_DESFIRE_ACCESS_SRC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIBS)

keydiversification_test: $(KEYDIVERSIFICATION_TEST_SRC)
	$(CC) $(KEYDIVERSIFICATION_TEST_SRC) $(CFLAGS_WITH_PTHREAD) $(LDFLAGS) -o $@ $(LIBS)

read_personalized: $(READ_PERSONALIZED_SRC)
	$(CC) $(READ_PRESONALIZED_SRC) $(CFLAGS_WITH_PTHREAD) $(LDFLAGS) -o $@ $(LIBS)

clean:
	@rm -rf $(PROGRAMS)
		    
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
#CFLAGS     += `pkg-config --cflags libfreefare pthread`
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
