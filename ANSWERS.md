# TP_Pyrochat_Deborah

PRISE EN MAIN

1. C'est une topologie en étoile car tous les échanges de données entre les clients passent par le serveur.

2. Dans les logs, on remarque que les messages envoyés entre les utilisateurs sur le réseau ne sont pas chiffrés avant d'etre stockés sur le serveur.

3. Si quelqu'un a accès au serveur il peut lire les messages envoyés entre les utilisateurs. En situation de confidentialité cette situation de non sécurité est préocupante.

4. Il faut utiliser une méthode de chiffrement pour protéger les messages et empecher leur lecture non authorisée. On a une méthode de chiffrement pour protéger les messages et empecher leur lecture non authorisée


CHIFFREMENT

1. Urandom est un générateur de nombres aléatoires sécurisé pour la cryptographie. Il utilise des sources d'entropie du système pour fournir des nombres imprévisibles. Il est important de s'assurer que le générateur est initialisé correctement pour garantir un niveau de sécurité approprié.

2. L'utilisation de primitives cryptographiques peut être dangereuse car elles peuvent être difficiles à implémenter correctement. Des erreurs peuvent créer des vulnérabilités qui mettent en danger la sécurité du système. Il est donc recommandé d'utiliser des bibliothèques cryptographiques bien testées par la communauté de la sécurité.

3. Malgré le chiffrement, un serveur malveillant peut encore exploiter des vulnérabilités pour nuire. Il peut manipuler les métadonnées, lancer des attaques "man-in-the-middle" ou analyser les schémas de trafic et les temps de connexion pour obtenir des informations sur les utilisateurs. S'il a accès à des informations sensibles, il peut déchiffrer et manipuler les données.

4. L'authentification manque ici. Elle permet de vérifier l'identité des interlocuteurs et la source des messages. Sans elle, un attaquant peut se faire passer pour un utilisateur légitime ou modifier les messages. Il est possible d'ajouter l'authentification en utilisant un mode d'opération de chiffrement comme GCM ou un code d'authentification de message (MAC) en combinaison avec le chiffrement.




 AUTHENTICATED SYMETRIC ENCRYPTION

1. Fernet est un moyen sûr et simple de chiffrer des messages. Il utilise des algorithmes éprouvés pour le chiffrement et l'authentification des messages, ce qui rend plus difficile la compromission de la sécurité. De plus, sa facilité d'utilisation réduit les risques d'erreurs ou d'oublis qui pourraient compromettre la sécurité.

2. Une attaque par rejeu est une méthode où un attaquant intercepte et réutilise un message légitime dans le but de tromper les destinataires en leur faisant croire qu'il provient d'une source fiable.

3. Pour se protéger contre les attaques par rejeu, on peut utiliser des "nonce" ou des "timestamps" qui garantissent que les messages sont uniques et récents. Les destinataires peuvent ainsi vérifier que les messages ne sont pas des faux.


TTL

1. Fernet est un moyen sûr et simple de chiffrer des messages. Il utilise des algorithmes éprouvés pour le chiffrement et l'authentification des messages, ce qui rend plus difficile la compromission de la sécurité. De plus, sa facilité d'utilisation réduit les risques d'erreurs ou d'oublis qui pourraient compromettre la sécurité.

2. Une attaque par rejeu est une méthode où un attaquant intercepte et réutilise un message légitime dans le but de tromper les destinataires en leur faisant croire qu'il provient d'une source fiable.

3. Pour se protéger contre les attaques par rejeu, on peut utiliser des "nonce" ou des "timestamps" qui garantissent que les messages sont uniques et récents. Les destinataires peuvent ainsi vérifier que les messages ne sont pas des faux.



ANALYSE CRITIQUE


Pour améliorer la sécurité de l'implémentation, on peut envisager d'utiliser des fonctions de dérivation de clés plus robustes, de mettre en œuvre un protocole d'échange de clés sécurisé et d'authentifier les parties à l'aide d'une infrastructure à clé publique. De plus, il faut s'assurer de gérer correctement les erreurs et les exceptions et de maintenir à jour les bibliothèques tierces utilisés.



