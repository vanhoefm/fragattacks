ALL=libeapol_auth.a

include ../lib.rules

install:
	@echo Nothing to be made.


LIB_OBJS = eapol_auth_sm.o eapol_auth_dump.o

libeapol_auth.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
