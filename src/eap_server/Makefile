ALL=libeap_server.a

include ../lib.rules

install:
	@echo Nothing to be made.


CFLAGS += -DCONFIG_HS20

LIB_OBJS= \
	eap_server.o \
	eap_server_identity.o \
	eap_server_methods.o

libeap_server.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
