# 🛰️ NetPulse-Audit : *Scanner de Reconnaissance Réseau & Services*

## -------------- Partie 1. Présentation du Projet -------------- 
**NetPulse-Audit** est un outil d'exploration **réseau** développé en **Python**. Il a pour **objectif** de **cartographier** un segment **réseau** (LAN) et d'analyser l'**exposition** des **services** sur chaque **hôte** découvert. Contrairement aux outils de scan basiques, il utilise des techniques de bas niveau pour maximiser la visibilité tout en restant discret.




---
---

## -------------- Partie 2. Avertissement Légal ⚠️ -------------- 
Cet outil est conçu pour un usage strictement **pédagogique** et **professionnel** dans le cadre **d'audits de sécurité autorisés**. L'auteur décline toute responsabilité en cas d'usage malveillant. Nous rappelons qu'il **strictement interdit** de scanner un réseau sans y avoir été autorisé par le propriétaire.


---
---


## ---------- Partie 3. Démarche d'audit *(Pédagogie & Technique)* 🛡️ ---------- 
L'audit suit une méthodologie rigoureuse divisée en trois phases distinctes :

#### ● Phase 1 : Découverte d'Hôtes *(Layer 2 - ARP)*
* **La démarche :** Le script émet une **requête ARP** en mode Broadcast à l'ensemble du sous-réseau.
* **Pourquoi l'ARP ?** Contrairement au Ping (ICMP) qui est souvent bloqué par les pare-feu Windows ou Linux, l'ARP est indispensable à la communication locale. Une machine active **doit** répondre à une requête **ARP** pour exister sur le réseau, ce qui permet de contourner le filtrage furtif.

#### ● Phase 2 : Scan de Ports Furtif *(Layer 4 - TCP Stealth Scan)*
* **La démarche :** Pour chaque IP découverte, le script initie un "Half-Open Scan". Il envoie un segment **TCP** avec le drapeau **SYN** (demande de synchronisation).

* **Analyse des réponses :**
    * **SYN-ACK reçu :** Le port est **🟢 ouvert**. Le script envoie alors immédiatement un segment **RST** (Reset) pour fermer la connexion avant qu'elle ne soit complétement établie. Cela évite d'être enregistré dans les journaux de connexion applicatifs de la cible.

    * **Pas de réponse :** Le port est considéré comme **🟠 Filtré** (présence probable d'un pare-feu).

#### ● Phase 3 : Identification & Empreinte (OS Fingerprinting & Banner Grabbing)
* **Détection d'OS :** Le script analyse la valeur du champ **TTL** (Time To Live) des paquets IP reçus. Un **TTL ≤ 64** suggère un système **Linux/Unix**, tandis qu'un **TTL ≤ 128** suggère un environnement **Windows**.

* **Banner Grabbing :** Pour les ports **ouverts**, une requête polie est envoyée au service (ex: requête HEAD pour le HTTP) afin de provoquer une réponse. Cela permet d'identifier le **logiciel** serveur (Nginx, Apache, SSH) et sa **version** si elle n'a pas été desactivé lors de configuration.

---
---
## -------------- Partie 4. Fonctionnalités Clés -------------- 
* **Résolution DNS :** Identification des noms d'hôtes pour une meilleure lisibilité.
* **Audit de Version :** Aide à l'identification de CVE (vulnérabilités) via la récupération des bannières.
* **Rapports Automatisés :** Génération de logs au format **JSON** structuré pour l'historisation.
* **Sécurité des données :** Gestion automatique des permissions Linux (chown/chmod) pour protéger les rapports générés par l'utilisateur root.

---
---
## -------------- Partie 5. Installation & Utilisation --------------  

1. **Dépendances :**
```bash
sudo pip install scapy
```

2. **Configuration :**
Éditez le fichier `data/data_port.json` pour définir la liste des services à auditer.

Le Fichier **data_port.json** est composé de liste de **Service** associé a un **port** : 

```json
{
    "Service": {
        "FTP": 21,
        "SSH": 22,
        "SMTP": 25,
        "HTTP": 80,
        "POP3" : 110,
        "IMAP" : 143,
        "HTTPS" : 443,
        "Mysql" : 3306,
        "PostgreSQL" : 5432
}
```

3. **Lancement :**
```bash
sudo python3 main_scan.py
```

---
---
## -------------- Partie 6. Exemple de sortie (JSON) -------------- 
#### ● Name File : *logs/AUDIT_Scan_NETWORK_(dateactuel).json*

```json
{
    "192.168.1.254": {
        "Name DNS": "livebox.home",
        "Addresse MAC": "02:fa:r3:98:c4:4e" ,
        "OS Detecte": "Linux/Unix",
        "21": {
            "statut" : "🔴 Fermé",
            "Service" : "FTP"
        }
        "80": {
            "statut": "🟢 OUVERT",
            "Service": "HTTP",
            "Banner": "Server: Nginx/"
        }
    }
}
```

---
---
## -------------- Partie 7. Conclusion -------------- 
À travers le développement de **NetPulse-Audit**, j'ai pu approfondir le forgeage de paquets avec Scapy, la manipulation des sockets TCP/IP et l'analyse comportementale des systèmes d'exploitation.

Au-delà de l'aspect technique, cet outil illustre l'importance de la visibilité sur un réseau : on ne peut protéger que ce que l'on connaît. Il pose les bases d'une gestion proactive de la sécurité, où l'identification précise des services et de leurs versions permet d'anticiper les vecteurs d'attaque avant qu'ils ne soient exploités.

---
- **Auteur** : Alexis Rousseau - **Ingénieur | Administrateur Systeme Réseau et Cybersécurité**
- **Date** 22/04/2026
