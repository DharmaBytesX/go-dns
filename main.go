package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Fonction pour créer l'en-tête DNS
func créerEntêteDNS() []byte {

	var transactionID uint16 = 64 // ID de transaction prédéfini (2 octets)
	var flags uint16 = 256        // 0x0100 (requête standard, récursion désirée)
	var questions uint16 = 1      // Nombre de questions
	var answers uint16 = 0        // Nombre de réponses
	var authority uint16 = 0      // Nombre de fichiers d'autorité
	var additional uint16 = 0     // Nombre de fichiers additionnels

	// Créer un tampon pour contenir les données binaires
	var tampon bytes.Buffer

	// Écrire chaque champ dans le tampon au format BigEndian
	binary.Write(&tampon, binary.BigEndian, transactionID)
	binary.Write(&tampon, binary.BigEndian, flags)
	binary.Write(&tampon, binary.BigEndian, questions)
	binary.Write(&tampon, binary.BigEndian, answers)
	binary.Write(&tampon, binary.BigEndian, authority)
	binary.Write(&tampon, binary.BigEndian, additional)

	// Retourner les données binaires sous forme de tranche d'octets
	return tampon.Bytes()
}

// Fonction pour encoder le QNAME (nom de domaine) dans la section de la question DNS
func créerQuestionQNAME(nomDeDomaine string) []byte {
	// Diviser le nom de domaine en étiquettes
	parties := strings.Split(nomDeDomaine, ".")

	// Créer un tampon pour contenir les données binaires
	var tampon bytes.Buffer

	// Encoder chaque étiquette
	for _, étiquette := range parties {
		// Écrire la longueur de l'étiquette (1 octet)
		binary.Write(&tampon, binary.BigEndian, uint8(len(étiquette)))

		// Écrire chaque caractère de l'étiquette (1 octet chacun)
		for _, caractère := range étiquette {
			binary.Write(&tampon, binary.BigEndian, uint8(caractère))
		}
	}

	// Écrire le terminateur nul (1 octet) pour le QNAME
	tampon.WriteByte(0x00)

	return tampon.Bytes()
}

// Fonction pour créer la question DNS complète avec QTYPE et QCLASS
func créerQuestionDNS(nomDeDomaine string) []byte {
	// Créer un tampon pour contenir les données binaires
	var tampon bytes.Buffer

	// Encoder le QNAME
	qname := créerQuestionQNAME(nomDeDomaine)
	tampon.Write(qname)

	// Écrire QTYPE (2 octets) - Pour un enregistrement A
	binary.Write(&tampon, binary.BigEndian, uint16(0x0001))

	// Écrire QCLASS (2 octets) - Pour IN (Internet)
	binary.Write(&tampon, binary.BigEndian, uint16(0x0001))

	return tampon.Bytes()
}

// Fonction pour envoyer une requête DNS et recevoir une réponse
func envoyerRequêteDNS(paquet []byte, serveurDNS string) ([]byte, error) {
	// Résoudre l'adresse du serveur DNS
	addr, err := net.ResolveUDPAddr("udp", serveurDNS+":53")
	if err != nil {
		return nil, fmt.Errorf("échec de la résolution de l'adresse : %v", err)
	}

	// Créer une connexion UDP avec le serveur DNS
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("échec de la connexion au serveur DNS : %v", err)
	}
	defer conn.Close()

	// Définir un délai d'attente pour la connexion
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Envoyer le paquet de requête DNS
	_, err = conn.Write(paquet)
	if err != nil {
		return nil, fmt.Errorf("échec de l'envoi de la requête DNS : %v", err)
	}

	// Tampon pour stocker la réponse
	réponse := make([]byte, 512) // Les réponses DNS sont généralement petites

	// Lire la réponse du serveur
	n, err := conn.Read(réponse)
	if err != nil {
		return nil, fmt.Errorf("échec de la lecture de la réponse DNS : %v", err)
	}

	// Retourner les octets reçus
	return réponse[:n], nil
}

// Fonction pour analyser la réponse DNS et extraire les réponses
func analyserRéponseDNS(réponse []byte) {
	// Analyser l'en-tête
	transactionID := binary.BigEndian.Uint16(réponse[0:2])
	flags := binary.BigEndian.Uint16(réponse[2:4])
	questions := binary.BigEndian.Uint16(réponse[4:6])
	answers := binary.BigEndian.Uint16(réponse[6:8])
	authority := binary.BigEndian.Uint16(réponse[8:10])
	additional := binary.BigEndian.Uint16(réponse[10:12])

	fmt.Printf("ID de transaction : %d\n", transactionID)
	fmt.Printf("Flags : 0x%04X\n", flags)
	fmt.Printf("Questions : %d\n", questions)
	fmt.Printf("Réponses : %d\n", answers)
	fmt.Printf("Autorité : %d\n", authority)
	fmt.Printf("Additionnel : %d\n", additional)

	// Ignorer la section de la question
	décalage := 12
	for i := 0; i < int(questions); i++ {
		for réponse[décalage] != 0 {
			décalage += int(réponse[décalage]) + 1
		}
		décalage += 5 // Ignorer l'octet nul et QTYPE (2 octets) et QCLASS (2 octets)
	}

	// Analyser la section des réponses
	for i := 0; i < int(answers); i++ {
		// Ignorer le champ de nom (soit un pointeur ou un nom complet)
		if réponse[décalage]&0xC0 == 0xC0 {
			// Nom compressé
			décalage += 2
		} else {
			// Nom complet
			for réponse[décalage] != 0 {
				décalage += int(réponse[décalage]) + 1
			}
			décalage++
		}

		// Lire le type, la classe, le TTL et la longueur des données
		qtype := binary.BigEndian.Uint16(réponse[décalage : décalage+2])
		qclass := binary.BigEndian.Uint16(réponse[décalage+2 : décalage+4])
		ttl := binary.BigEndian.Uint32(réponse[décalage+4 : décalage+8])
		longueurDonnées := binary.BigEndian.Uint16(réponse[décalage+8 : décalage+10])
		décalage += 10

		fmt.Printf("Réponse #%d :\n", i+1)
		fmt.Printf("  Type : %d\n", qtype)
		fmt.Printf("  Classe : %d\n", qclass)
		fmt.Printf("  TTL : %d\n", ttl)
		fmt.Printf("  Longueur des données : %d\n", longueurDonnées)

		// Lire les données de la réponse (ex. : adresse IP pour un enregistrement A)
		if qtype == 1 && qclass == 1 && longueurDonnées == 4 { // Enregistrement A, classe IN, IPv4
			ip := net.IP(réponse[décalage : décalage+4])
			fmt.Printf("  Adresse IP : %s\n", ip.String())
		} else {
			fmt.Printf("  Données : % X\n", réponse[décalage:décalage+int(longueurDonnées)])
		}
		décalage += int(longueurDonnées)
	}
}

func main() {

	// Récupérer les arguments de la ligne de commande, sans le nom du programme
	argsSansProg := os.Args[1:]

	// Créer l'en-tête DNS
	enTête := créerEntêteDNS()

	// Créer la section de la question DNS
	domaine := argsSansProg[0]
	question := créerQuestionDNS(domaine)

	// Combiner l'en-tête DNS et la question pour former le paquet DNS complet
	paquet := append(enTête, question...)

	// Serveur DNS pour envoyer la requête (serveur DNS public de Google)
	serveurDNS := "8.8.8.8"

	// Envoyer la requête DNS et recevoir la réponse
	réponse, err := envoyerRequêteDNS(paquet, serveurDNS)
	if err != nil {
		fmt.Printf("Erreur lors de l'envoi de la requête DNS : %v\n", err)
		return
	}

	// Analyser et afficher la réponse DNS
	analyserRéponseDNS(réponse)
}
