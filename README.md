Résolveur DNS Rudimentaire en Go
Ce projet implémente un résolveur DNS simple en Go, construit entièrement à partir de zéro sans utiliser de bibliothèques DNS externes. Il permet d'envoyer des requêtes DNS à un serveur DNS spécifique et d'analyser les réponses, offrant une compréhension approfondie du protocole DNS et de la manipulation des paquets.

Fonctionnalités
Génération d'en-têtes DNS et de questions DNS à partir de noms de domaine fournis par l'utilisateur.
Envoi de requêtes DNS à des serveurs DNS via UDP.
Analyse des réponses DNS reçues, y compris l'extraction des enregistrements de type A (IPv4).
Structure du Code
Création de l'en-tête DNS : L'en-tête DNS est généré avec les champs nécessaires tels que l'ID de transaction, les flags, et le nombre de questions.

Création de la question DNS : La section de la question DNS est construite en utilisant le nom de domaine fourni, encodé en labels (parties séparées par des points) avec leur longueur et les caractères ASCII.

Envoi de la requête DNS : La requête DNS est envoyée au serveur DNS de Google (8.8.8.8) via UDP, et la réponse est capturée.

Analyse de la réponse DNS : La réponse est analysée pour extraire les informations pertinentes, telles que les enregistrements d'adresse IP (type A).

Installation
Cloner le dépôt :

bash
Copier le code
git clone https://github.com/votre-utilisateur/votre-repository.git
cd votre-repository
Compiler le programme :

bash
Copier le code
go build -o dns_resolver main.go
Utilisation
Pour utiliser ce résolveur DNS, compilez le programme et exécutez-le en fournissant un nom de domaine comme argument.

Exemple de Commande
bash
Copier le code
./dns_resolver google.com
Explication des Étapes
Récupération du nom de domaine : Le nom de domaine est récupéré depuis les arguments de la ligne de commande.

Génération de l'en-tête DNS : L'en-tête DNS est créé avec les paramètres nécessaires pour une requête standard.

Création de la question DNS : La question DNS est construite en divisant le nom de domaine en labels.

Combinaison de l'en-tête et de la question : L'en-tête et la question sont combinés pour former un paquet DNS complet.

Envoi de la requête : La requête est envoyée au serveur DNS de Google (8.8.8.8).

Analyse de la réponse : La réponse est analysée et les résultats sont affichés, y compris les adresses IP associées au domaine.

Remarques
Ce projet est un résolveur DNS rudimentaire qui vise à illustrer les concepts de manipulation des paquets DNS. Il ne prend pas en charge des fonctionnalités avancées telles que le caching, le load balancing, ou d'autres types d'enregistrements DNS.
