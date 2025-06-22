default: all

CFLAGS += -Wall -Wextra -march=native -Ofast -pipe -I../include -flto -fuse-linker-plugin -MMD
LDFLAGS += -lgnutls -march=native -Ofast -pipe -flto -fuse-linker-plugin

CC = gcc
#CC = x86_64-w64-mingw32-gcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
#DEPENDS = $(SRCS:.c=.d)

all: berntlst

berntlst: $(OBJS)
	$(CC) $(OBJS) -o berntlst $(LDFLAGS)

#-include $(DEPENDS)

clean:
	$(RM) berntlst src/*.o src/*.d
