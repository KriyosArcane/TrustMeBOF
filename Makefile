CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Wno-unused-function -I include
SRCDIR = src
BINDIR = bin

SOURCES = $(wildcard $(SRCDIR)/tmb_*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%.o,$(SOURCES))

all: $(OBJECTS)
	@echo "[+] Built $(words $(OBJECTS)) BOFs"

$(BINDIR)/%.o: $(SRCDIR)/%.c include/tmb_bof.h include/beacon.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ -c $<
	@echo "  $@"

clean:
	rm -f $(BINDIR)/*.o

.PHONY: all clean
