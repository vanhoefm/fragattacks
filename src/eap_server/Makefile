include ../lib.rules

install:
	@echo Nothing to be made.


CFLAGS += -DCONFIG_HS20

LIB_OBJS= \
	eap_server.o \
	eap_server_identity.o \
	eap_server_methods.o

_OBJS_VAR := LIB_OBJS
include ../objs.mk
