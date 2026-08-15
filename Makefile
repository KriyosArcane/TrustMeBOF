CC = x86_64-w64-mingw32-gcc
CXX = x86_64-w64-mingw32-g++
CFLAGS = -Wall -Wno-unused-function -I include
CXXFLAGS = -Wall -Wno-unused-function -I include -std=c++17 -fno-exceptions -fno-rtti
SRCDIR = src
BINDIR = bin

C_SOURCES = $(wildcard $(SRCDIR)/tmb_*.c)
CXX_SOURCES = $(wildcard $(SRCDIR)/tmb_*.cpp)
C_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%.o,$(C_SOURCES))
CXX_OBJECTS = $(patsubst $(SRCDIR)/%.cpp,$(BINDIR)/%.o,$(CXX_SOURCES))
OBJECTS = $(C_OBJECTS) $(CXX_OBJECTS)

all: $(OBJECTS)
	@echo "[+] Built $(words $(OBJECTS)) BOFs"

$(BINDIR)/%.o: $(SRCDIR)/%.c include/tmb_bof.h include/beacon.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ -c $<
	@echo "  $@"

$(BINDIR)/%.o: $(SRCDIR)/%.cpp include/beacon.h
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) -o $@ -c $<
	@echo "  $@"

clean:
	rm -f $(BINDIR)/*.o

payload:
	$(CC) -shared -O2 -s -fno-ident -o sipexec/sipexec_payload_impersonate.dll \
		sipexec/sipexec_payload_impersonate.c -lkernel32 -ladvapi32
	@echo "  sipexec/sipexec_payload_impersonate.dll"
	$(CC) -shared -O2 -s -fno-ident -o sipexec/sipexec_loader.dll \
		sipexec/sipexec_loader.c -lkernel32
	@echo "  sipexec/sipexec_loader.dll"

.PHONY: all clean payload
