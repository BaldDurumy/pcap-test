#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

struct ethernet_hdr
{
    u_int8_t  ether_dhost[6];	/* destination ethernet address */
    u_int8_t  ether_shost[6];	/* source ethernet address */
    u_int16_t ether_type;		/* protocol */
};

struct ipv4_hdr
{
    u_int8_t ip_hl:4, ip_v:4;	/* version, header length*/
    u_int8_t ip_tos;			/* type of service */
    u_int16_t ip_len;         	/* total length */
    u_int16_t ip_id;          	/* identification */
    u_int16_t ip_off:13, ip_flag:3;	/* flag, fragment offset*/
    u_int8_t ip_ttl;          	/* time to live */
    u_int8_t ip_p;            	/* protocol */
    u_int16_t ip_sum;         	/* checksum */
    u_int32_t ip_src, ip_dst; 	/* source and dest address */
};

struct tcp_hdr
{
    u_int16_t th_sport;       	/* source port */
    u_int16_t th_dport;       	/* destination port */
    u_int32_t th_seq;          	/* sequence number */
    u_int32_t th_ack;          	/* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
    		th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

uint16_t ntohs(uint16_t n) {
	uint16_t n1 = (n & 0xff00) >> 8;
	uint16_t n2 = (n & 0x00ff) << 8;
	return n1 | n2;
}

uint32_t ntohl(uint32_t n){
	uint32_t n1 = (n & 0xff000000) >> 24;
	uint32_t n2 = (n & 0x00ff0000) >> 8;
	uint32_t n3 = (n & 0x0000ff00) << 8;
	uint32_t n4 = (n & 0x000000ff) << 24;
	return n1 | n2 | n3 | n4;
}

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		//My Code
		if(packet[23] != 0x06){
			printf("Not TCP packet\n");
			continue;
		}

		//Ethernet Header
		struct ethernet_hdr* pEther = packet;
		printf("\n===Ehternet Header===\n");
		printf("SRC MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", pEther->ether_shost[0], pEther->ether_shost[1], pEther->ether_shost[2], pEther->ether_shost[3], pEther->ether_shost[4], pEther->ether_shost[5]);
		printf("DST MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", pEther->ether_dhost[0], pEther->ether_dhost[1], pEther->ether_dhost[2], pEther->ether_dhost[3], pEther->ether_dhost[4], pEther->ether_dhost[5]);		

		//IP Header
		struct ipv4_hdr* pIpv4 = (u_int8_t*)pEther + sizeof(struct ethernet_hdr);
		printf("\n===Ipv4 Header===\n");
		printf("SRC IP : %d.%d.%d.%d\n", (pIpv4->ip_src & 0x000000ff), (pIpv4->ip_src & 0x0000ff00)>>8, (pIpv4->ip_src & 0x00ff0000)>>16, (pIpv4->ip_src & 0xff000000)>>24);
		printf("DST IP : %d.%d.%d.%d\n", (pIpv4->ip_dst & 0x000000ff), (pIpv4->ip_dst & 0x0000ff00)>>8, (pIpv4->ip_dst & 0x00ff0000)>>16, (pIpv4->ip_dst & 0xff000000)>>24);

		//TCP Header
		struct tcp_hdr* pTcp = (u_int8_t*)pIpv4 + sizeof(struct ipv4_hdr);
		printf("\n===TCP Header===\n");
		printf("SRC PORT : %d\n", ntohs(pTcp->th_sport));
		printf("DST PORT : %d\n", ntohs(pTcp->th_dport));

		//Payload(Data)
		u_int8_t* pPayload = (u_int8_t*)pTcp + sizeof(struct tcp_hdr);
		printf("\n===Payload(Data)===\n");
		for(int i = 0; i < 20; i++){
			if(i == 10){
				printf("\n");
			}
			printf("%02x ", pPayload[i]);
		}
		printf("\n\n");
	}

	pcap_close(pcap);
}
