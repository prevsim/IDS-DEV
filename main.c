#include "populate.h"
#include <string.h>
#include <syslog.h>

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

struct my_packet_handler_args{
        Rule *rules_ds;
        char **argv;
}typedef My_packet_handler_args;

void read_rules(FILE * file, Rule *rules_ds)
{
        file = fopen("ids.rules", "r");
        int line = 0;
        char chain[200];
        int msg = 0;
        int content = 0;
        char option[50];
        while(fgets(chain,200,file) != NULL)
        {
                sscanf(chain, "%s %s %s %s %s %s %s (%[^)]", rules_ds[line].action, rules_ds[line].protocol, rules_ds[line].shost,rules_ds[line].sport,
                rules_ds[line].direction, rules_ds[line].dhost, rules_ds[line].dport,option);
                printf("option : %s\n",option);
                strcpy(rules_ds[line].content,"");
                char delim[] ="\"";
                char *separation = strtok(option,delim);
                while (separation != NULL){
                        printf("Separation %s\n",separation);
                        if (strcmp(separation, "msg:") == 0){
                                msg = 1;
                        }
                        else if (msg == 1){
                                strcpy(rules_ds[line].msg,separation);
                                msg = 0;
                        }
                        else if (strcmp(separation, "; content:") == 0){
                                printf("ok\n");
                                content = 1;
                        }
                        else if (content == 1){
                                strcpy(rules_ds[line].content,separation);
                                content = 0;
                        }
                        separation = strtok(NULL,delim);
                        
                }
                printf("3 %s\n",rules_ds[line].msg);
                printf("4 %s\n",rules_ds[line].content);
                
                line ++;
        }
        
        
        fclose(file);
}
int condition_interminable_tcp(Rule rule, ETHER_Frame *frame){
        if(frame->data.payload_type == TCP_PROTOCOL){
                if ((strcmp(rule.shost,frame->data.source_ip)==0 || strcmp(rule.shost, "any") == 0) && (atoi(rule.sport) == frame->data.tcp_data.source_port || strcmp(rule.sport, "any") == 0 )
                && (strcmp(rule.dhost,frame->data.destination_ip) == 0 || strcmp(rule.dhost, "any") == 0) && (atoi(rule.dport) == frame->data.tcp_data.destination_port || strcmp(rule.dport,"any")== 0)){
                        return 1;
                }
                
                
                
        }
        return 0;
}

int condition_interminable_udp(Rule rule, ETHER_Frame *frame){
        if (frame->data.payload_type == UDP_PROTOCOL){
               if ((strcmp(rule.shost,frame->data.source_ip)==0 || strcmp(rule.shost, "any") == 0) && (atoi(rule.sport) == frame->data.udp_data.source_port || strcmp(rule.sport, "any") == 0 )
                && (strcmp(rule.dhost,frame->data.destination_ip) == 0 || strcmp(rule.dhost, "any") == 0) && (atoi(rule.dport) == frame->data.udp_data.destination_port || strcmp(rule.dport,"any")== 0)){
                        return 1;
                }
        }

        return 0;
}

void rule_http(Rule rule_http, ETHER_Frame *frame){
        if (frame->data.payload_type == TCP_PROTOCOL){
                if (frame->data.tcp_data.source_port == 80 || frame->data.tcp_data.destination_port == 80){
                        if (condition_interminable_tcp(rule_http,frame) == 1){
                                if (strstr(frame->data.tcp_data.data, rule_http.content) != NULL){
                                        syslog(LOG_ALERT,"%s",rule_http.msg);
                                }
                        }
                }
        }
}
void rule_udp(Rule rule_udp,ETHER_Frame *frame){
        if (condition_interminable_udp(rule_udp,frame) == 1){
                syslog(LOG_ALERT,"%s",rule_udp.msg);
        }
}
void rule_tcp(Rule rule_tcp,ETHER_Frame *frame){
        if (condition_interminable_tcp(rule_tcp,frame) == 1){
                syslog(LOG_ALERT,"%s",rule_tcp.msg);
        }
}


void rule_matcher(Rule *rules_ds, ETHER_Frame *frame,int rules_ds_size)
{       
      for (size_t i = 0; i < rules_ds_size; i++){
              if (strcmp(rules_ds[i].protocol,"http") == 0){
                        if (frame->data.tcp_data.source_port == 443){
                                printf("Packet crypté\n");
                         }
                        else{
                                rule_http(rules_ds[i],frame);
                        }
              }
              else if (strcmp(rules_ds[i].protocol,"tcp") == 0){
                      rule_tcp(rules_ds[i],frame);
              }
              else if (strcmp(rules_ds[i].protocol,"udp") == 0){
                      rule_udp(rules_ds[i],frame);
              } 
              
      }
          

}

int count_line(FILE * file, char *argv[]){
        char line[100];
        int count = 0;
        file = fopen(argv[1],"r");
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
void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){
        My_packet_handler_args *args2 = (My_packet_handler_args *)args;
        ETHER_Frame custom_frame;
        populate_packet_ds(header, packet, &custom_frame);
        FILE * file;
        int count = count_line(file,args2->argv);
        rule_matcher(args2->rules_ds, &custom_frame,count);
        
        
}


int main(int argc, char **argv) 
{
        
        if (argc != 2){
                printf("Il faut mettre 2 arguments.IL faut passer le fichier de règles en 2ieme argument");
                return 1;
        }
        FILE * file;
        
        char *device = "eth0";
        char error_buffer[PCAP_ERRBUF_SIZE];
        int count = count_line(file,argv);

        Rule rules_ds[count];
        read_rules(file,rules_ds);

        My_packet_handler_args args;
        args.rules_ds = rules_ds;
        args.argv = argv;
            
        pcap_t *handle;
        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
        int total_packet_count = 20;

        pcap_loop(handle, total_packet_count, my_packet_handler, (u_char *)&args);

        
        return 0;
        
}
