#!/usr/bin/env python3
"""
ShadowLink C2 Server
Phase 1: TCP Listener - Établir une connexion avec l'agent
"""

# TODO: Importer les modules nécessaires pour les sockets
import socket

# TODO: Définir les constantes (HOST, PORT)
HOST = "127.0.0.1"
PORT = 4444

def main():
    """Point d'entrée principal du serveur"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    
    s.listen(1)
    
    print("Server Listening ... ")
    
    try:
        
        while True:
            
            (client_socket, address_client) = s.accept()
            
            printable = f"Votre addresse est {address_client[0]}\n"
            print(f"Connexion client, {address_client[0]}\n")
            
            client_socket.send(printable.encode("utf-8"))
            data_recv = client_socket.recv(1024)
            
            print(f"Reçu : {data_recv.decode('utf-8')}")
            
            client_socket.close()
            
            if not data_recv:
                break
            
            
            
            
            
    except KeyboardInterrupt:
        print("Serveur closing ... ")
        s.close()

if __name__ == "__main__":
    print("[*] ShadowLink C2 Server - Phase 1")
    main()
