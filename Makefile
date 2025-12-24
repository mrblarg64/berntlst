default: berntlst
CC = gcc
CFLAGS += -Wall -Wextra -march=native -Ofast -pipe -I../include -flto -fuse-linker-plugin -MMD
LDFLAGS += -lgnutls -march=native -Ofast -pipe -flto -fuse-linker-plugin

#default: berntlst.exe
#CC = x86_64-w64-mingw32-gcc
#STRIP = x86_64-w64-mingw32-strip
#CFLAGS += -mconsole -Wall -Wextra -Ofast -pipe -I/home/brian/Documents/brisrc/win32-vista-newer/include
#LDFLAGS += -static -mconsole -Ofast -pipe -lqwave

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
#DEPENDS = $(SRCS:.c=.d)



windows: berntlst.exe
linux: berntlst

berntlst.exe: $(OBJS)
	libtool --tag=CC --mode=link $(CC) $(OBJS) $(LDFLAGS) -o berntlst.exe /home/brian/Documents/brisrc/win32-vista-newer/lib/libgnutls.la
	$(STRIP) berntlst.exe

berntlst: $(OBJS)
	$(CC) $(OBJS) -o berntlst $(LDFLAGS)

#-include $(DEPENDS)

clean:
	$(RM) berntlst berntlst.exe src/*.o src/*.d
