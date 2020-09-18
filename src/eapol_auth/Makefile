ALL=libeapol_auth.a

include ../lib.rules

install:
	@echo Nothing to be made.


LIB_OBJS = eapol_auth_sm.o eapol_auth_dump.o

_OBJS_VAR := LIB_OBJS
include ../objs.mk
libeapol_auth.a: $(LIB_OBJS)
	$(AR) crT $@ $?
