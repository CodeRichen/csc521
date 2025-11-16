# The target name of the executable
NAME= lab4

# Configuration of compiler and linker
SRCDIR := src
OBJDIR := build

# --- Modify here: lib2
LIBDIR := ../lib2/src
CONFIG := config

CC := gcc
FLAGS := $(shell cat $(CONFIG) | awk '/^[^\#]+$$/ {print "-D"$$0}' ORS=' ')
CFLAGS := -g -O2 -Wall -fsanitize=address $(FLAGS)

# --- Modify here: lib2 include
INCLUDES := -Isrc -I../lib2/include

LDFLAGS := -lpcap -fsanitize=address

# Find all of the .c files in SRCDIR.
SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

# --- Modify here: library source list stays the same
LIB_SRCS := util.c netdevice.c arp.c arptable.c ip.c icmp.c tcp.c udp.c dns.c
LIB_OBJS := $(addprefix $(OBJDIR)/, $(LIB_SRCS:.c=.o))

# --- Modify here: LIB_SRCS prefix becomes lib2
LIB_SRCS := $(addprefix $(LIBDIR)/, $(LIB_SRCS))

.PHONY: all clean
all: $(NAME)
	@echo "Successfully built $(NAME)"

$(NAME): $(OBJS) $(LIB_OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJS): $(OBJDIR)/%.o: $(SRCDIR)/%.c $(CONFIG) | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LIB_OBJS): $(OBJDIR)/%.o: $(LIBDIR)/%.c $(CONFIG) | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	-rm $(NAME)
	-rm -rf $(OBJDIR)
