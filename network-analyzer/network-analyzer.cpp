#include <pcap.h> 
#include <stdio.h> 
#include <iostream>

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    std::cout << "Pacchetto intercettato! Lunghezza: " << header->len << " bytes" << std::endl;
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