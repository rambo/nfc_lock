CC         = gcc
CFLAGS     = -g -Wall -std=gnu99
LDFLAGS    =
PROGRAMS   =

PROGRAMS += mifare-desfire-access
MIFARE_DESFIRE_ACCESS_SRC = mifare-desfire-access.c

PROGRAMS += cmac_example
CMAC_EXAMPLE_SRC = cmac_example.c

PROGRAMS += keydiversification_test
KEYDIVERSIFICATION_TEST_SRC = keydiversification.c helpers.c keydiversification_test.c

PROGRAMS += read_personalized
READ_PRESONALIZED_SRC = keydiversification.c helpers.c read_personalized.c

PROGRAMS += pre_personalize
PRE_PRESONALIZE_SRC = keydiversification.c helpers.c pre_personalize.c

PROGRAMS += de_personalize
DE_PRESONALIZE_SRC = keydiversification.c helpers.c de_personalize.c

PROGRAMS += pthread_example
PTHREAD_EXAMPLE_SRC = pthread_example.c

PROGRAMS += req_test
REQ_TEST_SRC = req_test.c

PROGRAMS += gatekeeper
GATEKEEPER_SRC = keydiversification.c helpers.c gatekeeper.c



CFLAGS_WITH_PTHREAD = $(CFLAGS) -pthread
CFLAGS_WITH_ZMQ = $(shell pkg-config --cflags libzmq) $(CFLAGS) 
LIBS_WITH_ZMQ = $(shell pkg-config --libs libzmq) $(LIBS) 

CFLAGS	+= -g $(shell pkg-config --cflags libfreefare openssl) -lrt
LDFLAGS	+= -g
LIBS 	+= $(shell pkg-config --libs libfreefare openssl) 

all: $(PROGRAMS)

mifare-desfire-access: $(MIFARE_DESFIRE_ACCESS_SRC)
	$(CC) $(MIFARE_DESFIRE_ACCESS_SRC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIBS)

keydiversification_test: $(KEYDIVERSIFICATION_TEST_SRC)
	$(CC) $(KEYDIVERSIFICATION_TEST_SRC) $(CFLAGS_WITH_PTHREAD) $(LDFLAGS) -o $@ $(LIBS)

read_personalized: $(READ_PERSONALIZED_SRC)
	$(CC) $(READ_PRESONALIZED_SRC) $(CFLAGS_WITH_PTHREAD) $(LDFLAGS) -o $@ $(LIBS)

pre_personalize: $(PRE_PRESONALIZE_SRC)
	$(CC) $(PRE_PRESONALIZE_SRC) $(CFLAGS_WITH_PTHREAD) $(LDFLAGS) -o $@ $(LIBS)

de_personalize: $(DE_PRESONALIZE_SRC)
	$(CC) $(DE_PRESONALIZE_SRC) $(CFLAGS_WITH_PTHREAD) $(LDFLAGS) -o $@ $(LIBS)

pthread_example: $(PTHREAD_EXAMPLE_SRC)
	$(CC) $(PTHREAD_EXAMPLE_SRC) $(CFLAGS_WITH_PTHREAD) $(LDFLAGS) -o $@ $(LIBS)

cmac_example: $(CMAC_EXAMPLE_SRC)
	$(CC) $(CMAC_EXAMPLE_SRC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIBS)

req_test: $(REQ_TEST_SRC)
	$(CC) $(REQ_TEST_SRC) $(CFLAGS_WITH_ZMQ) $(LDFLAGS) -o $@ $(LIBS_WITH_ZMQ)

gatekeeper: $(GATEKEEPER_SRC)
	$(CC) $(GATEKEEPER_SRC) $(CFLAGS_WITH_ZMQ) -pthread $(LDFLAGS) -o $@ $(LIBS_WITH_ZMQ)


clean:
	@rm -rf $(PROGRAMS)


