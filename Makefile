# ShadowLink C2 Framework - Makefile
# Pour compiler l'agent Windows et gérer le serveur Python

.PHONY: all server agent clean help test

# Variables
CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lws2_32 -static
AGENT_SRC = agent/agent.c
AGENT_OUT = agent/agent.exe
SERVER_SRC = server/server.py
PYTHON = python3

all: help

help:
	@echo "=== ShadowLink C2 Framework ==="
	@echo ""
	@echo "Commandes disponibles:"
	@echo "  make agent          - Compile l'agent Windows (nécessite mingw-w64)"
	@echo "  make server         - Lance le serveur Python"
	@echo "  make install-deps   - Installe les dépendances Python"
	@echo "  make clean          - Nettoie les fichiers compilés"
	@echo "  make test           - Lance les tests"
	@echo ""

# Compilation de l'agent Windows
agent:
	@echo "[*] Compilation de l'agent Windows..."
	$(CC) $(CFLAGS) $(AGENT_SRC) -o $(AGENT_OUT) $(LDFLAGS)
	@echo "[+] Agent compilé: $(AGENT_OUT)"

# Lancement du serveur Python
server:
	@echo "[*] Démarrage du serveur C2..."
	$(PYTHON) $(SERVER_SRC)

# Installation des dépendances Python
install-deps:
	@echo "[*] Installation des dépendances Python..."
	$(PYTHON) -m pip install -r server/requirements.txt

# Nettoyage
clean:
	@echo "[*] Nettoyage..."
	rm -f $(AGENT_OUT)
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "[+] Nettoyage terminé"

# Tests
test:
	@echo "[*] Lancement des tests..."
	$(PYTHON) -m pytest tests/ -v
