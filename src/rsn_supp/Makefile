ALL=librsn_supp.a

include ../lib.rules

install:
	@echo Nothing to be made.


CFLAGS += -DCONFIG_IEEE80211R
CFLAGS += -DCONFIG_TDLS
CFLAGS += -DCONFIG_WNM
CFLAGS += -DIEEE8021X_EAPOL

LIB_OBJS= \
	pmksa_cache.o \
	wpa_ft.o \
	tdls.o \
	preauth.o \
	wpa.o \
	wpa_ie.o

_OBJS_VAR := LIB_OBJS
include ../objs.mk
librsn_supp.a: $(LIB_OBJS)
	$(AR) crT $@ $?
