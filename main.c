#include "populate.h"
#include <string.h>

struct ids_rule
{
        char action[6];
        char protocol[6];
        char shost[IP_ADDR_LEN_STR];
        char sport[5];
        char direction[3];
        char dhost[IP_ADDR_LEN_STR];
        char dport[5];
        char msg[50];
        char content[50];
} typedef Rule;


void read_rules(FILE * file, Rule *rules_ds)
{
        file = fopen("ids.rules", "r");
        int line = 0;
        char chain[200];
        while(fgets(chain,200,file) != NULL)
        {
                sscanf(chain, "%s %s %s %s %s %s %s (%[^)])", rules_ds[line].action, rules_ds[line].protocol, rules_ds[line].shost,rules_ds[line].sport,
                rules_ds[line].direction, rules_ds[line].dhost, rules_ds[line].dport, rules_ds[line].content);
                printf("content %s\n",rules_ds[line].content);
                printf("Protocole = %s\n", rules_ds[line].protocol);
                int size_content = strlen(rules_ds[line].content);

                char delim[] ="\"";
                char *separation = strtok(rules_ds[line].content,delim);

                while (separation != NULL)
                {
                        printf("Separation %s\n ",separation);
                        separation = strtok(NULL,delim);
                }
                
                line ++;
        }
        
        
        fclose(file);
       
        
        
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

int count_line(FILE * file){
        char line[100];
        int count = 0;
        file = fopen("ids.rules","r");
        if(file == NULL){
                printf("Erreur lors de l'ouverture du fichier\n");
                fclose(file);
                return 0;
        }
        while(fgets(line,100,file) != NULL){
                count ++;
        }
        fclose(file);
        return count;       
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
        FILE * file;
        char *device = "eth0";
        char error_buffer[PCAP_ERRBUF_SIZE];
        int count = count_line(file);
        Rule rules_ds[count];
        read_rules(file,rules_ds);
        pcap_t *handle;

        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
        int total_packet_count = 20;

        pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

        return 0;
}
