#include <pcap.h> 
#include <stdio.h> 
#include <iostream>

/* Gli indirizzi Ethernet sono di 6 byte */
#define ETHER_ADDR_LEN 6

/* Intestazione Ethernet */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Indirizzo host di destinazione */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Indirizzo host di origine */
	u_short ether_type; /* IP? ARP? RARP? ecc. */
};

/* Intestazione IP */
struct sniff_ip {
	u_char ip_vhl; /* versione << 4 | lunghezza intestazione >> 2 */
	u_char ip_tos; /* tipo di servizio */
	u_short ip_len; /* lunghezza totale */
	u_short ip_id; /* identificazione */
	u_short ip_off; /* campo di offset del frammento */
#define IP_RF 0x8000 /* flag di frammento riservato */
#define IP_DF 0x4000 /* flag di non frammentazione */
#define IP_MF 0x2000 /* flag per più frammenti */
#define IP_OFFMASK 0x1fff /* maschera per la frammentazione dei bit */
	u_char ip_ttl; /* tempo di vita */
	u_char ip_p; /* protocollo */
	u_short ip_sum; /* checksum */
	struct in_addr ip_src,ip_dst; /* indirizzo sorgente e destinazione */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* Intestazione TCP */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport; /* porta sorgente */
	u_short th_dport; /* porta di destinazione */
	tcp_seq th_seq; /* numero di sequenza */
	tcp_seq th_ack; /* numero di riconoscimento */
	u_char th_offx2; /* offset dati, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win; /* finestra */
	u_short th_sum; /* checksum */
	u_short th_urp; /* puntatore urgente */
};

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    // Puntatori alle varie intestazioni
    const struct sniff_ethernet *ethernet; 
    const struct sniff_ip *ip;              
    const struct sniff_tcp *tcp;            

    int size_ip;
    int size_tcp;

    // 1. Identifichiamo l'header Ethernet (inizia a inizio pacchetto, offset 0)
    ethernet = (struct sniff_ethernet*)(packet);

    // 2. Identifichiamo l'header IP (inizia subito dopo l'Ethernet, ovvero dopo 14 byte)
    ip = (struct sniff_ip*)(packet + 14);
    
    // Calcoliamo la dimensione effettiva dell'header IP (moltiplicato per 4)
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        // Un header IP valido deve essere lungo almeno 20 byte
        return; 
    }

    // Controlliamo se il protocollo è effettivamente TCP (il valore è 6)
    if (ip->ip_p != IPPROTO_TCP) {
        // Se non è TCP (magari è UDP o ICMP), saltiamo questo pacchetto per ora
        return; 
    }

    // 3. Identifichiamo l'header TCP (inizia dopo l'header Ethernet + header IP)
    tcp = (struct sniff_tcp*)(packet + 14 + size_ip);
    
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        return;
    }

    // 4. STAMPA DEI DATI ESTRATTI
    // inet_ntoa converte l'indirizzo IP binario in una stringa leggibile (es. "192.168.1.5")
    std::cout << "[TCP] " 
              << inet_ntoa(ip->ip_src) << ":" << ntohs(tcp->th_sport)
              << " -> " 
              << inet_ntoa(ip->ip_dst) << ":" << ntohs(tcp->th_dport)
              << " (" << header->len << " bytes)" 
              << std::endl;
}

int main(int argc, char *argv[]) 
{ 
	pcap_t *handle; /* Handle di sessione */ 
	char *dev = argv[1]; /* Il dispositivo su cui effettuare lo sniffing */ 
	char errbuf[PCAP_ERRBUF_SIZE]; /* Stringa di errore */ 
	struct pcap_pkthdr header; /* L'intestazione che pcap ci fornisce */ 
	const u_char *packet; /* Il pacchetto effettivo */ 

	
	if (dev == NULL) { 
		fprintf(stderr, "Impossibile trovare il dispositivo predefinito: %s\n", errbuf); 
		return(2); 
	} 
	
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
	if (handle == NULL) { 
		fprintf(stderr, "Impossibile aprire il dispositivo %s: %s\n", dev, errbuf); 
		return(2); 
	} 
	
	std::cout << "Sessione avviata correttamente. In ascolto..." << std::endl;

    
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return(0);
}