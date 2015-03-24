CC         = gcc
CFLAGS     = -g -Wall -std=gnu99 -fstack-protector
LDFLAGS    =
PROGRAMS   =

PROGRAMS += mifare-desfire-access
MIFARE_DESFIRE_ACCESS_SRC = mifare-desfire-access.c

PROGRAMS += cmac_example
CMAC_EXAMPLE_SRC = cmac_example.c

PROGRAMS += keydiversification_test
KEYDIVERSIFICATION_TEST_SRC = keydiversification.c helpers.c log.c keydiversification_test.c

PROGRAMS += read_personalized
READ_PRESONALIZED_SRC = keydiversification.c helpers.c log.c smart_node_config.c dumb_node_config.c read_personalized.c

PROGRAMS += pre_personalize
PRE_PERSONALIZE_SRC = keydiversification.c helpers.c log.c smart_node_config.c dumb_node_config.c pre-personalize_config.c pre_personalize.c

PROGRAMS += de_personalize
DE_PRESONALIZE_SRC = keydiversification.c helpers.c log.c pre-personalize_config.c de_personalize.c

PROGRAMS += personalize
PERSONALIZE_SRC = keydiversification.c helpers.c log.c smart_node_config.c dumb_node_config.c pre-personalize_config.c personalize.c

PROGRAMS += pthread_example
PTHREAD_EXAMPLE_SRC = pthread_example.c

PROGRAMS += req_test
REQ_TEST_SRC = req_test.c

PROGRAMS += log_test
LOG_TEST_SRC = log.c log_test.c


PROGRAMS += gatekeeper
GATEKEEPER_SRC = keydiversification.c helpers.c log.c smart_node_helpers.c smart_node_config.c dumb_node_config.c gatekeeper.c



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

pre_personalize: $(PRE_PERSONALIZE_SRC)
	$(CC) $(PRE_PERSONALIZE_SRC) $(CFLAGS_WITH_PTHREAD) $(LDFLAGS) -o $@ $(LIBS)

personalize: $(PERSONALIZE_SRC)
	$(CC) $(PERSONALIZE_SRC) $(CFLAGS_WITH_PTHREAD) $(LDFLAGS) -o $@ $(LIBS)

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

log_test: $(LOG_TEST_SRC)
	$(CC) $(LOG_TEST_SRC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIBS)


clean:
	@rm -rf $(PROGRAMS)


