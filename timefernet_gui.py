import time
from cryptography.fernet import Fernet, InvalidToken
from FernetGUI import FernetGUI

TTL = 30

class TimeFernet(Fernet):
    # Étend la classe Fernet pour inclure des fonctionnalités de temps
    def encrypt_at_time(self, data, timestamp):
        # Convertit le temps en IV
        iv = self._current_time_to_iv(timestamp)
        # Chiffre les données en utilisant l'IV
        return self._encrypt_from_parts(data, timestamp, iv)

    def decrypt_at_time(self, token, timestamp, ttl):
        # Vérifie que le token n'a pas expiré
        timestamp, data = Fernet._get_unverified_token_data(token)
        if timestamp + ttl < time.time():
            raise InvalidToken("Token has expired")
        # Déchiffre les données
        return self.decrypt(token)

class TimeFernetGUI(FernetGUI):
    # Étend la classe FernetGUI pour inclure des fonctionnalités de temps
    def encrypt(self, message):
        fernet = TimeFernet(self.key)
        current_time = int(time.time())
        # Chiffre le message en utilisant Fernet à l'heure actuelle
        encrypted_message = fernet.encrypt_at_time(message.encode(), current_time)
        # Renvoie le message chiffré
        return encrypted_message

    def decrypt(self, encrypted_message):
        fernet = TimeFernet(self.key)
        current_time = int(time.time())
        try:
            # Déchiffre le message en utilisant Fernet à l'heure actuelle
            decrypted_message = fernet.decrypt_at_time(encrypted_message, current_time, ttl=TTL)
            # Renvoie le message déchiffré
            return decrypted_message.decode()
        except InvalidToken as e:
            # Affiche une erreur si le token a expiré
            self._log(f"Error: {e}")
            return None

