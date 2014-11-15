##CC         = gcc
##CFLAGS     = -g -Wall -std=gnu99
##LDFLAGS    =
##
##PROGRAM = mifare-desfire-access
##PROGRAM_FILES = mifare-desfire-access.c
##
##CFLAGS	+= -g $(shell pkg-config --cflags libfreefare)
##LDFLAGS	+= -g
##LIBS 	+= $(shell pkg-config --libs libfreefare) 
##
##all: $(PROGRAM)
##
##%: %.c 
##	$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)
##
##clean:
##	@rm -rf $(PROGRAM)
##		    
#
# Set up basic variables:
CC         = gcc
CFLAGS     = -c -Wall -std=gnu99
LDFLAGS    =

# List of sources:
SOURCES    = mifare-desfire-access.c
OBJECTS    = $(SOURCES:.c=.o)

# Name of executable target:
EXECUTABLE = mifare-desfire-access 

CFLAGS     += `pkg-config --cflags libfreefare`
LDFLAGS    += `pkg-config --libs libfreefare`


all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) 

.c.o:
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm $(OBJECTS) $(EXECUTABLE)

