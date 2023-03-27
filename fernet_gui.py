import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from CipheredGUI import CipheredGUI

# Constantes
SALT = b'\x00' * 16
ITERATIONS = 100000

class FernetGUI(CipheredGUI):

    def encrypt(self, message):
        # Crée un objet Fernet avec la clé
        fernet = Fernet(self.key)
        
        # Chiffre le message en utilisant Fernet
        encrypted_message = fernet.encrypt(message.encode())
        
        # Renvoie le message chiffré
        return encrypted_message

    def decrypt(self, encrypted_message):
        # Crée un objet Fernet avec la clé
        fernet = Fernet(self.key)
        
        # Déchiffre le message en utilisant Fernet
        decrypted_message = fernet.decrypt(encrypted_message)
        
        # Renvoie le message déchiffré
        return decrypted_message.decode()

    def run_chat(self, password):
        # Utilise PBKDF2HMAC pour dériver une clé à partir du mot de passe et d'un salt
        kdf = PBKDF2HMAC(
            algorithm=hashlib.sha256(),
            length=32,
            salt=SALT,
            iterations=ITERATIONS
        )
        
        # Génère la clé à partir du mot de passe et du sel
        key_material = kdf.derive(password.encode())
        
        # Encode la clé en base64 pour une utilisation avec Fernet
        self.key = base64.urlsafe_b64encode(key_material)