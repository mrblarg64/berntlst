default: linux

VERSION = 1.7

SRCS = $(wildcard src/*.c)

CC = gcc

OBJS.linux = $(patsubst src/%.c, obj/%.o, $(SRCS))
CFLAGS.linux += -Wall -Wextra -march=native -Ofast -pipe -flto -fuse-linker-plugin -MMD
LDFLAGS.linux += -lgnutls -march=native -Ofast -pipe -flto -fuse-linker-plugin


BINPREFIX.32bit = i686-w64-mingw32-
BINPREFIX.64bit = x86_64-w64-mingw32-
STRIP = $(BINPREFIX)strip

CFLAGS.win = -mconsole -Wall -Wextra -Ofast -pipe
LDFLAGS.win = -mconsole -Ofast -pipe 
#Windows 10 1703 newer
CFLAGS.10-1703-newer.64bit = -DNTDDI_VERSION=NTDDI_WIN10_RS2 -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00 -I/home/brian/Documents/brisrc/win32-vista-newer/include
GNUTLS_PATH.10-1703-newer.64bit = /home/brian/Documents/brisrc/win32-vista-newer/lib/libgnutls.la
CFLAGS.10-1703-newer.32bit = -DNTDDI_VERSION=NTDDI_WIN10_RS2 -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00 -I/home/brian/Documents/brisrc/win32-vista-newer-i686/include
GNUTLS_PATH.10-1703-newer.32bit = /home/brian/Documents/brisrc/win32-vista-newer-i686/lib/libgnutls.la
LDFLAGS.10-1703-newer = -lqwave
########################
#Windows Vista newer
CFLAGS.vista-newer.64bit = -DWINVER=0x0600 -D_WIN32_WINNT=0x0600 -I/home/brian/Documents/brisrc/win32-vista-newer/include
GNUTLS_PATH.vista-newer.64bit = /home/brian/Documents/brisrc/win32-vista-newer/lib/libgnutls.la
CFLAGS.vista-newer.32bit = -DWINVER=0x0600 -D_WIN32_WINNT=0x0600 -I/home/brian/Documents/brisrc/win32-vista-newer-i686/include
GNUTLS_PATH.vista-newer.32bit = /home/brian/Documents/brisrc/win32-vista-newer-i686/lib/libgnutls.la
LDFLAGS.vista-newer += -lqwave
########################
#Windows Server 2003 newer
CFLAGS.server-2003-newer.64bit += -DWINVER=0x0502 -D_WIN32_WINNT=0x0502 -I/home/brian/Documents/brisrc/win32-server-2003-newer/include
GNUTLS_PATH.server-2003-newer.64bit = /home/brian/Documents/brisrc/win32-server-2003-newer/lib/libgnutls.la
CFLAGS.server-2003-newer.32bit += -DWINVER=0x0502 -D_WIN32_WINNT=0x0502 -I/home/brian/Documents/brisrc/win32-server-2003-newer-i686/include
GNUTLS_PATH.server-2003-newer.32bit = /home/brian/Documents/brisrc/win32-server-2003-newer-i686/lib/libgnutls.la
########################
#NT 4 - 95, NT 3?
CFLAGS.nt-4-newer.32bit += -DWINVER=0x0400 -D_WIN32_WINNT=0x0400 -mconsole -Wall -Wextra -Ofast -pipe -I/home/brian/Documents/brisrc/win32-nt-4-newer-i686/include
GNUTLS_PATH.nt-4-newer.32bit = /home/brian/Documents/brisrc/win32-nt-4-newer-i686/lib/libgnutls.la

WINDOWS_VERSIONS = 10-1703-newer vista-newer server-2003-newer #nt-4-newer
WINDOWS_BITS = 32bit 64bit

.PHONY: all
.PHONY: windows
.PHONY: linux

all: linux windows

linux: berntlst

windows: $(foreach bits, $(WINDOWS_BITS), $(foreach winver, $(WINDOWS_VERSIONS), berntlst-$(VERSION)-$(winver)-$(bits).exe)) berntlst-$(VERSION)-nt-4-newer-32bit.exe

define winexe =
OBJS.$$$(1)-$$$(2) = $(patsubst src/%.c, obj-$$$(1)-$$$(2)/%.o, $(SRCS))

obj-$$$(1)-$$$(2)/%.o: src/%.c | obj-$$$(1)-$$$(2)
	$$(BINPREFIX.$$$(2))$(CC) $$(CFLAGS.win) $$(CFLAGS.$$$(1).$$$(2)) -c -o $$@ $$<

obj-$$$(1)-$$$(2):
	mkdir $$@

berntlst-$$(VERSION)-$$$(1)-$$$(2).exe: $$(OBJS.$$$(1)-$$$(2))
	libtool --tag=CC --mode=link $$(BINPREFIX.$$$(2))$(CC) $$(OBJS.$$$(1)-$$$(2)) $$(LDFLAGS.win) $$(LDFLAGS.$$$(1)) -o $$@ $$(GNUTLS_PATH.$$$(1).$$$(2))
	$$(BINPREFIX.$$$(2))$$(STRIP) $$@
endef

$(foreach bits, $(WINDOWS_BITS), $(foreach winver, $(WINDOWS_VERSIONS), $(eval $(call winexe, $(winver), $(bits)))))
$(eval $(call winexe, nt-4-newer, 32bit))

berntlst: $(OBJS.linux)
	$(CC) $(OBJS.linux) -o berntlst $(LDFLAGS.linux)

obj/%.o: src/%.c | obj
	$(CC) $(CFLAGS.linux) -c -o $@ $<

obj:
	mkdir $@

#-include $(DEPENDS)

clean:
	$(RM) berntlst *.exe obj*/*
	rmdir obj* .libs
