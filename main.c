#include "populate.h"
#include <string.h>

struct ids_rule
{
} typedef Rule;

void read_rules(FILE * file, Rule *rules_ds, int count)
{
        /*const struct option_trame *trame;

        trame = (struct option_trame*)(packet_body);
        printf("Destination address : %s", trame_dhost);*/
        /*Cette fonction doit récolter les Frames qui passent sur le réseau et repérer les informations suivantes:
        L'adresse ip, le port de destination, le message, le contenu afin de reconnaitre le protocole
        Une fois ces informations enregistrées, on passe la main à la fonction rule_matcher
        */
}

void rule_matcher(Rule *rules_ds, ETHER_Frame *frame)
{
        /*Cette fonction est chargée de repérer si il y a un match entre une Frame reçue et un type d'alerte enregistrée dans le fichier ids.rules
        Le fichier ids.rules reprend les règles à appliquer à chaque Frame. Exemple: 
        Une Frame est retenue, on va analyser son ip, son port de destination (ces infos ont étés sauvées dans la fonction précédente) et son contenu. Si le port de destination est
        le port 80 alors il s'agira d'une Frame http. Et si dans le contenu il y a "malware.exe", alors on sait qu'il s'agit d'une attaque
        => On dira qu'il y a un match et il faudra inscrire dans le fichier syslog l'erreur "shell attack" car c'est le message qu'il faut écrire dans les logs en cas d'attaque
        sur le protocole http (c'est précisé dans le fichier ids.rules)
        */
}


void my_packet_handler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
)

{
        ETHER_Frame custom_frame;
        populate_packet_ds(header, packet, &custom_frame);


}

int main(int argc, char *argv[]) 
{

        char *device = "eth0";
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
        int total_packet_count = 20;

        pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

        return 0;
}
