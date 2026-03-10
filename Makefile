CC      ?= gcc
AR      ?= ar
SRCDIR   := src
INCDIR   := include
BUILDDIR := build
LIBDIR   := $(BUILDDIR)/lib
BINDIR   := $(BUILDDIR)/bin
OBJDIR   := $(BUILDDIR)/obj
LIB      := $(LIBDIR)/liblogger.a
CFLAGS := -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter -I$(INCDIR) -O2
LDFLAGS := -lpthread
LIB_SRCS := \
	$(SRCDIR)/core/logger_core.c \
	$(SRCDIR)/core/logger_storage.c \
	$(SRCDIR)/core/logger_crash.c \
	$(SRCDIR)/crypto/logger_crypto.c \
	$(SRCDIR)/protection/logger_protection.c \
	$(SRCDIR)/transport/logger_transport.c
LIB_OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(LIB_SRCS))
.PHONY: all lib apps clean
all: lib apps
lib: $(LIB)
$(LIB): $(LIB_OBJS)
	@mkdir -p $(LIBDIR)
	$(AR) rcs $@ $^
	@echo "[LIB] $@"
apps: $(BINDIR)/log_sender $(BINDIR)/log_receiver
$(BINDIR)/log_sender: apps/sender/sender_main.c $(LIB)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $< -L$(LIBDIR) -llogger $(LDFLAGS) -o $@
	@echo "[BIN] $@"
$(BINDIR)/log_receiver: apps/receiver/receiver_main.c $(LIB)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $< -L$(LIBDIR) -llogger $(LDFLAGS) -o $@
	@echo "[BIN] $@"
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "[CC]  $<"
clean:
	rm -rf $(BUILDDIR)
