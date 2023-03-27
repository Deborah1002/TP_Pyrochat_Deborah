from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from tkinter import Entry, Label, Button
import os
from basic_gui import BasicGUI

# Constantes pour la dérivation de clé et le chiffrement
KEY_LENGTH = 32
IV_LENGTH = 16
BLOCK_SIZE = 128
ITERATIONS = 100000

# Texte à afficher pour la fenêtre de connexion
PASSWORD_LABEL_TEXT = "Mot de passe :"
PASSWORD_ENTRY_WIDTH = 20
PASSWORD_BUTTON_TEXT = "Enregistrer"

# Messages d'erreur
SAVE_PASSWORD_ERROR = "Veuillez entrer un mot de passe."
KEY_ERROR = "La clé de chiffrement n'a pas été dérivée."

class CipheredGUI(BasicGUI):
    def __init__(self, key=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._key = key
        
    # Création de la fenêtre de connexion avec champ de mot de passe
    def _create_connection_window(self):
        super()._create_connection_window()

        # Création des éléments de la fenêtre
        password_label = Label(self.connection_window, text=PASSWORD_LABEL_TEXT)
        self.password_entry = Entry(self.connection_window, show="*", width=PASSWORD_ENTRY_WIDTH)
        password_button = Button(self.connection_window, text=PASSWORD_BUTTON_TEXT, command=self._save_password)

        # Placement des éléments dans la fenêtre
        password_label.grid(row=3, column=0, padx=(10, 5), pady=(10, 0), sticky="e")
        self.password_entry.grid(row=3, column=1,padx=(5, 10), pady=(10, 0), sticky="w")
        password_button.grid(row=4, column=0, columnspan=2, padx=(10, 10), pady=(10, 10))
        
    # Enregistrement du mot de passe dans la variable _key
    def _save_password(self):
        password = self.password_entry.get()
        if password:
            # Génération d'un sel aléatoire
            salt = os.urandom(IV_LENGTH)
            
            # Définition de la fonction de dérivation de clé
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=KEY_LENGTH,
                salt=salt,
                iterations=ITERATIONS,
                backend=default_backend()
            )
            
            # Dérivation de la clé à partir du mot de passe
            self._key = kdf.derive(password.encode())
            
            # Effacement du champ de mot de passe
            self.password_entry.delete(0, 'end')
            
            # Affichage d'un message de confirmation
            self._log("Mot de passe enregistré.")
        else:
            # Affichage d'un message d'erreur si le champ est vide
            self._log(SAVE_PASSWORD_ERROR)

    # Vérification que la clé a été dérivée avant de lancer la conversation
    def run_chat(self):
        if self._key is None:
            self._log(KEY_ERROR)
            return

        super().run_chat()

   
      # Chiffrement du texte
    def encrypt(self, plaintext):
        if self._key is None:
        # Vérification que la clé a été dérivée avant de chiffrer
           raise ValueError(KEY_ERROR)

    # Génération d'un vecteur d'initialisation aléatoire
        iv = os.urandom(IV_LENGTH)
    
    # Création d'un objet Cipher pour le chiffrement AES-CTR
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())
    
    # Création des objets encryptor et padder
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(BLOCK_SIZE).padder()
    
    # Ajout du padding au texte à chiffrer
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    # Chiffrement du texte
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    # Retourne le vecteur d'initialisation et le texte chiffré
        return (iv, encrypted)

# Déchiffrement du texte
    def decrypt(self, encrypted_data):
        if self._key is None:
        # Vérification que la clé a été dérivée avant de déchiffrer
           raise ValueError(KEY_ERROR)

    # Récupération du vecteur d'initialisation et du texte chiffré
        iv, encrypted = encrypted_data[:IV_LENGTH], encrypted_data[IV_LENGTH:]
    
    # Création d'un objet Cipher pour le déchiffrement AES-CTR
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())
    
    # Création de l'objet decryptor
        decryptor = cipher.decryptor()
    
    # Déchiffrement du texte
        decrypted_data = decryptor.update(encrypted) + decryptor.finalize()
    
    # Suppression du padding
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    # Retourne le texte déchiffré
        return unpadded_data.decode('utf-8')

# Envoie d'un message chiffré
    def send(self, msg):
        encrypted_msg = self.encrypt(msg)
        encrypted_data = b"".join(encrypted_msg)
        super().send(encrypted_data)

# Réception et déchiffrement d'un message
    def recv(self):
        encrypted_data = super().recv()
        iv, encrypted = encrypted_data[:IV_LENGTH], encrypted_data[IV_LENGTH:]
        encrypted_msg = (iv, encrypted)
        decrypted_msg = self.decrypt(encrypted_msg)
        return decrypted_msg
