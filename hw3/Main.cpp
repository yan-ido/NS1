// Network Security 1 Homework - FMI
// prints the source MAC, destination MAC, ethernet type, source IP, destination IP, IP protocol, TCP source port, TCP destination port, way of scanning (Null or Xmas)
// for every packet from a given pcap file
// tested and executed on Microsoft Visual Studio 2013

// 1. install WinPcap - http://www.winpcap.org/devel.htm
// 2. Configuration Properties -> C/C++ -> General -> Additional Include Directories - Add ..\WpdPack\Include
// 3. Configuration Properties -> C/C++ -> Preprocessor -> Preprocessor Definitions - Add WIN32;WPCAP;HAVE_REMOTE
// 4. Configuration Properties -> Linker -> General -> Additiona Library Directories - Add ..\WpdPack\Lib
// 5. Configuration Properties -> Linker -> Input -> Additional Dependancies - Add wpcap.lib;Packet.lib;Ws2_32.lib

#include<iostream>
#include<pcap.h>
#include<string>

using namespace std;

struct ether_header // creating a structure for the ethernet header
{
	unsigned char dest_mac[6]; // destination MAC address
	unsigned char src_mac[6]; // source MAC address
	unsigned short ether_type; // ethernet type
};

struct ip_header
{
	unsigned char iph_len : 4; // IP header length
	unsigned char ip_version : 4; //version
	unsigned char tos; // type of service
	unsigned short tot_len; // total length
	unsigned short id; // identification
	unsigned short frag_off; // fragment offset + flags
	unsigned char ip_ttl; // time to live
	unsigned char ip_protocol; // protocol (TCP, UDP etc.)
	unsigned short ip_checksum; // IP checksum
	unsigned char src_ip[4]; // source address
	unsigned char dest_ip[4]; // destination IP
};

struct tcp_header
{
	unsigned short src_port; // source port
	unsigned short dest_port; // destination port
	unsigned int seq; // sequence number
	unsigned int ack_seq; // acknowledge sequence

	unsigned short res1 : 4; // reserver 1 : 4 bits
	unsigned short doff : 4; //data offset
	unsigned short fin : 1; // finish flag
	unsigned short syn : 1; // synchronize flag
	unsigned short rst : 1; // reset flag
	unsigned short psh : 1; // push flag
	unsigned short ack : 1; // acknowledge flag
	unsigned short urg : 1; // urgent flag
	unsigned short ecn : 1; // ECN-Echo flag
	unsigned short cwr : 1; // congestion window reduced flag

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
};

bool IsPacketNull(tcp_header * tcp) // returning true if all the tcp flags are set to 0
{
	return (tcp->fin == 0 && tcp->syn == 0 && tcp->rst == 0 && tcp->psh == 0
		&& tcp->ack == 0 && tcp->urg == 0 && tcp->ecn == 0 && tcp->cwr == 0);
}

bool IsPacketXmas(tcp_header * tcp) // returning true if ONLY fin, psh and urg flags are set to 1
{
	return (tcp->fin == 1 && tcp->syn == 0 && tcp->rst == 0 && tcp->psh == 1
		&& tcp->ack == 0 && tcp->urg == 1 && tcp->ecn == 0 && tcp->cwr == 0);
}

int main(int args, char *argv[])
{
	cin >> argv[0];
	string file = argv[0]; // getting the file name

	char errbuff[PCAP_ERRBUF_SIZE]; // holding the error
	pcap_t *pcap = pcap_open_offline(file.c_str(), errbuff); // opening the file

	struct pcap_pkthdr *header; // header
	const u_char *data; // containing the data
	struct ether_header * eth; // creating an object to hold the data for the ethernet header of every packet
	struct ip_header * ip; // creating an object to hold the data for the ip header of every packet
	struct tcp_header * tcp; // creating an object to hold the data for the tcp header of every packet

	while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) // looping through the different packets from the file and reading the data
	{
		if (header->len != header->caplen)
			printf("Packet size is different than the capture size.");

		eth = (struct ether_header *) data; // converting the data into eth
		ip = (struct ip_header *)(data + 14); // converting the data into ip header (with 14 shift for the ethernet header)
		if (ip->ip_protocol != 6) // if ip protocol is not 6, it's not TCP and should not continue
		{
			continue;
		}
		tcp = (struct tcp_header *)(data + 14 + ip->iph_len * 4); // converting the data into tcp header (with 14 shirt for the ethernet header and ip header length)

		if (IsPacketNull(tcp) == true || IsPacketXmas(tcp) == true)
		{
			fprintf(stdout, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x ",
				eth->src_mac[0], eth->src_mac[1], eth->src_mac[2], eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]); // printing surce MAC
			fprintf(stdout, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x ", eth->dest_mac[0],
				eth->dest_mac[1], eth->dest_mac[2], eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5]); // printing destination MAC
			fprintf(stdout, "0x%.4X ", ntohs(eth->ether_type)); // printing ethernet type

			fprintf(stdout, "%d.%d.%d.%d ", ip->src_ip[0], ip->src_ip[1], ip->src_ip[2], ip->src_ip[3]); // printing source ip
			fprintf(stdout, "%d.%d.%d.%d ", ip->dest_ip[0], ip->dest_ip[1], ip->dest_ip[2], ip->dest_ip[3]); // printing destination ip
			fprintf(stdout, "%d ", ip->ip_protocol); // printing ip protocol

			fprintf(stdout, "%d ", ntohs(tcp->src_port)); // printing tcp source port
			fprintf(stdout, "%d ", ntohs(tcp->dest_port)); // printing tcp destination port

			if (IsPacketNull(tcp) == true) // packet is Null
			{
				printf("Null\n");
			}
			else // packet is Xmas
			{
				printf("Xmas\n");
			}
		}
	} // end of while
} // end of main