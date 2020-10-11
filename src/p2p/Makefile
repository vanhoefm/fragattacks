ALL=$(OUT)libp2p.a

include ../lib.rules

install:
	@echo Nothing to be made.


CFLAGS += -DCONFIG_WIFI_DISPLAY
CFLAGS += -DCONFIG_WPS_NFC

LIB_OBJS= \
	p2p_build.o \
	p2p.o \
	p2p_dev_disc.o \
	p2p_go_neg.o \
	p2p_group.o \
	p2p_invitation.o \
	p2p_parse.o \
	p2p_pd.o \
	p2p_sd.o \
	p2p_utils.o

_OBJS_VAR := LIB_OBJS
include ../objs.mk
$(OUT)libp2p.a: $(LIB_OBJS)
	$(AR) crT $@ $?
