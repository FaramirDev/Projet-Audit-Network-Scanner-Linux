from scapy.all import ARP, Ether, srp, IP, TCP, sr1
from datetime import date, datetime
import json, socket, os

## Import DATA json PORT
path_data_file = "data/data_port.json"
with open(path_data_file, 'r') as f:
    data_port = json.load(f)

## DEF fonction scan
def scan_host(ip_range):
    list_ip_scan = []
    ## 1. Creation du Paquet (Ethernet/ARP)
    ## Premiere Couche 'adresse mac' dst => Envoie a tout le monde
    mac_diffusion = "ff:ff:ff:ff:ff:ff"
    ## Deuxieme Couche ARP avec l'ip range (pdst = ip cible ou plage /24)
    paquet = Ether(dst=mac_diffusion) / ARP(pdst=ip_range)

    ## 2. Envoie & Reception via rcp
    # rcp utilise deux liste : repondu et non-repondu
    reponses, non_reponses = srp(paquet, timeout=2, verbose=False)

    ## 3. Traitement
    # Chaque element de Reponses est un couple (paquet_envoyé avec .psrc, paquet_recu avec .hwsrc)
    for envoye, recu in reponses:
        recup_ip_recu = recu.psrc
        recup_mac = recu.hwsrc
        tuple_ip_mac = (recup_ip_recu,recup_mac)
        list_ip_scan.append(tuple_ip_mac)

        print(f"IP : {recup_ip_recu} | MAC : {recu.hwsrc}")

    return list_ip_scan

recup_scan_ip = scan_host("192.168.1.0/24")

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip,port))

        ## Check si WEB demande de baniere
        if port in [80,443]:
            s.send(b"HEAD /1.1\r\nHost: test\r\n\r\n")
            banner = s.recv(1024)
        else: 
            ## Check SI SSH/FTP 
            banner = s.recv(1024)

        return banner.decode(errors='ignore').strip()

    except Exception as e:
        return f"erreur : {e}"
    finally:
        s.close()

def get_hostname(ip):
    try:
        check_tuple_host = socket.gethostbyaddr(ip)
        recup_name = check_tuple_host[0]

    except:
        recup_name = "Aucun nom DNS"

    return recup_name

def scanner_port(list_ip, dict_data_port):
    dic_data_port = dict_data_port["SERVICES"]

    dic_all_scan_data = {}

    ## ANALYSE :
    # Si reponse est NONE : Machine n'a pas repondu (Firewall ?)
    # Si reponse a une couche TCP -> Verification des Flags
    ##### Si Flag = 0x12 (SYN-ACK) : Port Ouvert
    ##### Si Flag = 0x14 (RST) : Port est Fermé 
  
    for ip in list_ip:
        ## SET UP DIC port SCAN for DATA 
        data_scan_port = {}

        recup_ip, *_ = ip
        _, recup_mac = ip

        data_scan_port["Addresse MAC"] = recup_mac

        print(f"\n--- SCAN IP : {recup_ip} | Mac : {recup_mac} ---")
              
        ## RECUP NAME DNS - CHECK
        recup_name_dns = get_hostname(recup_ip)
        print(f"Name DNS : {recup_name_dns} ")
        data_scan_port["Name DNS"] = recup_name_dns             

        for service in dic_data_port: 
            ## RECUP NAME & PORT 
            recup_int_port = dic_data_port[service]

            ## Construction du paquet avec le FLAG SYN ("S") -> Demande 
            paquet = IP(dst=recup_ip) / TCP(dport=recup_int_port, flags="S")

            ## Envoi du Paquet pour Test (1seul paquet)
            reponse = sr1(paquet, timeout=1, verbose=False)

            ## Check reception != None
            if reponse is not None: 
                ## CHECK Si Reponse contient du TCP (Filtrage) & Check du Flag SYN-ACK (0x12)
                if reponse.haslayer(TCP) and reponse.getlayer(TCP).flags == 0x12:
                    print(f"Service : {service} | Port {recup_int_port} : 🟢 OUVERT")

                    ## CHECK Detection OS via TTL 
                    ttl_value = reponse.getlayer(IP).ttl
                    if ttl_value <= 64:
                        os_guess = "Linux/Unix"
                    elif ttl_value <= 128: 
                        os_guess = "Windows"
                    else:
                        os_guess = "Inconnu" 

                    ## print console
                    print(f"OS Detecte : {os_guess}")

                    ## RECUP Data for dic
                    data_scan_port["OS Detecte"] = os_guess

                    ## Check Banner 
                    banniere = grab_banner(recup_ip, recup_int_port)
                    print(f"    [!] Banniere : {banniere}")

                    ## Envoie d'un RST pour close 
                    sr1(IP(dst=recup_ip)/TCP(dport=recup_int_port, flags="R"), timeout=1, verbose=False) 

                    ## Recup data scan 
                    data_scan_port[recup_int_port] = {
                        "statut" : "🟢 OUVERT",
                        "Service" : service,
                        "Banner" : banniere
                    }

                else:
                    ## Cest un RST ou autre ?
                    print(f"Service : {service} | Port {recup_int_port} : 🔴 Fermé ou Autre ")

                    ## Recup data scan 
                    data_scan_port[recup_int_port] = {
                        "statut" : "🔴 Fermé",
                        "Service" : service,
                    }

                    pass
            else:
                print(f"Service : {service} | Port {recup_int_port} : 🟠 FILTRÉ (Pare-feu")

                ## Recup data scan 
                data_scan_port[recup_int_port] = {
                    "statut" : "🟠 Filtré (Pare-feu)",
                    "Service" : service,
                }

        ## data scan 
        dic_all_scan_data[recup_ip] = data_scan_port

    return dic_all_scan_data

data_scan = scanner_port(recup_scan_ip, data_port)

### Ecriture d'un fichier LOG JSON
path_write_log = "logs/"
os.makedirs("logs", exist_ok=True)

## Setup Name
# Date ACTUEL
date_today = datetime.now().strftime("%Y-%m-%d-%H%M")
# Name LOG
name_file_log = f"logs/AUDIT_Scan_NETWORK_{date_today}.json"

## Ecriture du Fichier Json 
with open(name_file_log, "w") as f:
    json.dump(data_scan, f, indent=4)
    print(f"\n>>> Rapport Sauvegarde {name_file_log}")

## Changement permission du fichier logs
uid = int(os.environ.get('SUDO_UID', 0))
gid = int(os.environ.get('SUDO_GID', 0))

if uid != 0:
    os.chown(name_file_log, uid, gid)
    os.chmod(name_file_log, 0o644)

