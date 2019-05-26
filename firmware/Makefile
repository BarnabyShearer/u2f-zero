SDK = $(HOME)/bin/SimplicityStudio_v4/developer/sdks/8051/v4.1.6
TOOLCHAIN = $(HOME)/bin/SimplicityStudio_v4/developer/toolchains/keil_8051/9.53/BIN
export WINEPREFIX = $(HOME)/.config/SimplicityStudio/v4/studio-wine

INCDIR = \
    $(SDK)/Device/shared/si8051Base;\
    $(SDK)/Device/EFM8UB3/inc;\
    $(SDK)/Lib/efm8_assert;\
    $(SDK)/Lib/efm8_usb/inc;\
    $(SDK)/Device/EFM8UB3/peripheral_driver/inc;\
    inc/config;\
    inc;\
    tests

LIBS = \
    Device/EFM8UB3/peripheral_driver/src/usb_0.OBJ \
    Lib/efm8_usb/src/efm8_usbd.OBJ \
    Lib/efm8_usb/src/efm8_usbdch9.OBJ \
    Lib/efm8_usb/src/efm8_usbdep.OBJ \
    Lib/efm8_usb/src/efm8_usbdint.OBJ \
    Lib/efm8_assert/assert.OBJ

CCONF = OMF2 LARGE ROM\(LARGE\) WARNINGLEVEL \(2\) FLOATFUZZY\(3\) \
    OPTIMIZE\(8,SPEED\) INTVECTOR\(0x0000\) INTPROMOTE \
    INCDIR\("$(INCDIR)"\) COND PAGEWIDTH \(120\) PAGELENGTH \(65\)

LXCONF = REMOVEUNUSED PAGEWIDTH \(120\) PAGELENGTH \(65\) \
    CLASSES\( \
        ECODE\(C:0x0 - C:0x9dfe\), \
        HCONST\(C:0x0 - C:0x9dfe\), \
        XDATA\(X:0x0 - X:0xbff\), \
        HDATA\(X:0x0 - X:0xbff\)\
    \)

SRC = $(wildcard src/*.c) $(wildcard tests/*.c)
# Keil tools exit code 1 is warnings only, so don't treat as an error in make
RC := test $$? -lt 2

EMPTY :=
SPACE := $(EMPTY) $(EMPTY)
COMMA := ,

all: setup/FIRMWARE.HEX build/FIRMWARE.HEX

clean:
	-rm -Rf setup build

build/%.OBJ :: %.c
	-mkdir -p "$(dir $@)"
	wine "$(TOOLCHAIN)/C51" "$<" $(CCONF) PRINT\("$(@:%.OBJ=%.LST)"\) OA OBJECT\("$@"\) || $(RC)

setup/%.OBJ :: %.c
	-mkdir -p "$(dir $@)"
	wine "$(TOOLCHAIN)/C51" "$<" $(CCONF) DF\(ATECC_SETUP_DEVICE\) PRINT\("$(@:%.OBJ=%.LST)"\) OA OBJECT\("$@"\) || $(RC)

build/%.OBJ :: $(SDK)/%.c
	-mkdir -p "$(dir $@)"
	wine "$(TOOLCHAIN)/C51" "$<" $(CCONF) PRINT\("$(@:%.OBJ=%.LST)"\) OA OBJECT\("$@"\) || $(RC)

build/FIRMWARE.OMF: $(addprefix build/,$(LIBS)) $(subst .c,.OBJ,$(addprefix build/,$(SRC)))
	wine "$(TOOLCHAIN)/LX51" $(subst $(SPACE),$(COMMA),$+) TO "$@" $(LXCONF) PRINT\("$(@:%.OMF=%.M51)"\) || $(RC)

setup/FIRMWARE.OMF: $(addprefix build/,$(LIBS)) $(subst .c,.OBJ,$(addprefix setup/,$(SRC)))
	wine "$(TOOLCHAIN)/LX51" $(subst $(SPACE),$(COMMA),$+) TO "$@" $(LXCONF) PRINT\("$(@:%.OMF=%.M51)"\) || $(RC)

%.HEX: %.OMF
	wine "$(TOOLCHAIN)/Ohx51" "$+" HEXFILE \("$@"\) H386

