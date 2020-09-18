ALL=libeapol_supp.a

include ../lib.rules

install:
	@echo Nothing to be made.


CFLAGS += -DIEEE8021X_EAPOL

LIB_OBJS = eapol_supp_sm.o

libeapol_supp.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
