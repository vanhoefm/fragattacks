ALL=$(OUT)libl2_packet.a

include ../lib.rules

install:
	@echo Nothing to be made.


LIB_OBJS = l2_packet_linux.o

_OBJS_VAR := LIB_OBJS
include ../objs.mk
$(OUT)libl2_packet.a: $(LIB_OBJS)
	$(AR) crT $@ $?
