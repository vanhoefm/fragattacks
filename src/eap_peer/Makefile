ALL=$(OUT)libeap_peer.a

include ../lib.rules

install:
	if ls *.so >/dev/null 2>&1; then \
		install -d $(DESTDIR)$(LIBDIR)/wpa_supplicant && \
		cp *.so $(DESTDIR)$(LIBDIR)/wpa_supplicant \
	; fi


CFLAGS += -DIEEE8021X_EAPOL

LIB_OBJS= \
	eap.o \
	eap_methods.o

_OBJS_VAR := LIB_OBJS
include ../objs.mk
$(OUT)libeap_peer.a: $(LIB_OBJS)
	$(AR) crT $@ $?
