ALL=libradius.a

include ../lib.rules

install:
	@echo Nothing to be made.


CFLAGS += -DCONFIG_IPV6

LIB_OBJS= \
	radius.o \
	radius_client.o \
	radius_das.o \
	radius_server.o

_OBJS_VAR := LIB_OBJS
include ../objs.mk
libradius.a: $(LIB_OBJS)
	$(AR) crT $@ $?
