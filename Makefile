default: berntlst
CC = gcc
CFLAGS += -Wall -Wextra -march=native -Ofast -pipe -I../include -flto -fuse-linker-plugin -MMD
LDFLAGS += -lgnutls -march=native -Ofast -pipe -flto -fuse-linker-plugin

#default: berntlst.exe
#BINPREFIX = i686-w64-mingw32-
#BINPREFIX = x86_64-w64-mingw32-
#CC = $(BINPREFIX)gcc
#STRIP = $(BINPREFIX)strip
#Windows 10 19H1 newer
#CFLAGS += -DNTDDI_VERSION=NTDDI_WIN10_19H1 -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00 -mconsole -Wall -Wextra -Ofast -pipe -I/home/brian/Documents/brisrc/win32-vista-newer/include
#GNUTLS_PATH = /home/brian/Documents/brisrc/win32-vista-newer/lib/libgnutls.la
#CFLAGS += -DNTDDI_VERSION=NTDDI_WIN10_19H1 -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00 -mconsole -Wall -Wextra -Ofast -pipe -I/home/brian/Documents/brisrc/win32-vista-newer-i686/include
#GNUTLS_PATH = /home/brian/Documents/brisrc/win32-vista-newer-i686/lib/libgnutls.la
#LDFLAGS += -mconsole -Ofast -pipe -lqwave
########################
#Windows Vista newer
#CFLAGS += -DWINVER=0x0600 -D_WIN32_WINNT=0x0600 -mconsole -Wall -Wextra -Ofast -pipe -I/home/brian/Documents/brisrc/win32-vista-newer/include
#GNUTLS_PATH = /home/brian/Documents/brisrc/win32-vista-newer/lib/libgnutls.la
#CFLAGS += -DWINVER=0x0600 -D_WIN32_WINNT=0x0600 -mconsole -Wall -Wextra -Ofast -pipe -I/home/brian/Documents/brisrc/win32-vista-newer-i686/include
#GNUTLS_PATH = /home/brian/Documents/brisrc/win32-vista-newer-i686/lib/libgnutls.la
#LDFLAGS += -mconsole -Ofast -pipe -lqwave
########################
#Windows Server 2003 newer
#CFLAGS += -DWINVER=0x0502 -D_WIN32_WINNT=0x0502 -mconsole -Wall -Wextra -Ofast -pipe -I/home/brian/Documents/brisrc/win32-server-2003-newer/include
#GNUTLS_PATH = /home/brian/Documents/brisrc/win32-server-2003-newer/lib/libgnutls.la
#CFLAGS += -DWINVER=0x0502 -D_WIN32_WINNT=0x0502 -mconsole -Wall -Wextra -Ofast -pipe -I/home/brian/Documents/brisrc/win32-server-2003-newer-i686/include
#GNUTLS_PATH = /home/brian/Documents/brisrc/win32-server-2003-newer-i686/lib/libgnutls.la
#LDFLAGS += -mconsole -Ofast -pipe
########################
#NT 4 - 95, NT 3?
#CFLAGS += -DWINVER=0x0400 -D_WIN32_WINNT=0x0400 -mconsole -Wall -Wextra -Ofast -pipe -I/home/brian/Documents/brisrc/win32-nt-4-newer-i686/include
#GNUTLS_PATH = /home/brian/Documents/brisrc/win32-nt-4-newer-i686/lib/libgnutls.la
#LDFLAGS += -mconsole -Ofast -pipe




SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
#DEPENDS = $(SRCS:.c=.d)



windows: berntlst.exe
linux: berntlst

berntlst.exe: $(OBJS)
	libtool --tag=CC --mode=link $(CC) $(OBJS) $(LDFLAGS) -o berntlst.exe $(GNUTLS_PATH)
	$(STRIP) berntlst.exe

berntlst: $(OBJS)
	$(CC) $(OBJS) -o berntlst $(LDFLAGS)

#-include $(DEPENDS)

clean:
	$(RM) berntlst berntlst.exe src/*.o src/*.d
