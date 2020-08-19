#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string>
#include <iostream>
#include <cstring>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define IP_PROTOCOL 2048
#define TCP_PROTOCOL 6
#define PORT_HTTP 80

const unsigned char *malicious_host;

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);
		// dump(data, ret);
	}
	fputc('\n', stdout);

	return id;
}

u_int32_t parse_http_host(const unsigned char *http_payload, const int payload_len, const unsigned char *host_name, const int host_len)
{
	// -- second line 
	// HTTP: [hostname]\r\n
	std::string str_payload (reinterpret_cast<char const*> (http_payload), payload_len);
	std::string host_filter (reinterpret_cast<char const*> (host_name), host_len);

	int first_line_end, second_line_start, second_line_end;
	first_line_end = str_payload.find("\r\n");
	second_line_start = str_payload.find(" ", first_line_end+2) + 1;
	second_line_end = str_payload.find("\r\n", first_line_end+2);

	std::string host = str_payload.substr(second_line_start, second_line_end - second_line_start);
	std::cout << host << std::endl;

	if (host.compare(host_filter) == 0) {
		printf("   malicious host!!!\n");
		return 0;
	}
	else 
		return 1;
}


u_int32_t check_url (struct nfq_data *tb) 
{
	printf("in check_url function!!\n");
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *data;

	// ip filtering
	ph = nfq_get_msg_packet_hdr(tb);
	if (!ph) {
		printf("nfq_get_msg_packet_hdr error\n");
		return 1;
	}
	if (ntohs(ph->hw_protocol) != IP_PROTOCOL) {
		printf("not ip\n");
		return 1;
	}

	// get total length of the packet
	int payload_len = nfq_get_payload(tb, &data);
	if (payload_len < 0) {
		printf("not received\n");
		return 1;
	}

	// tcp filtering
	struct iphdr *ip_header = (struct iphdr *) data;
	if (ip_header->protocol != TCP_PROTOCOL) {
		printf("not tcp\n");
		return 1;
	}
	int ip_head_size = ip_header->ihl * 4;
	payload_len -= ip_head_size;

	// http filtering and get payload of application layer
	struct tcphdr *tcp_header = (struct tcphdr *) (data + ip_head_size);
	int tcp_head_size = tcp_header->th_off * 4;
	payload_len -= tcp_head_size;

	// http request
	if (ntohs(tcp_header->th_dport) == PORT_HTTP) {
		// unsigned char host[256] = "test.gilgil.net";
		// int host_len = strlen((char *) host);
		int host_len = strlen((char *) malicious_host);

		// host url 비교
		printf("HTTP Request\n");
		// dump(data + ip_head_size + tcp_head_size, payload_len);
		return parse_http_host(data+ip_head_size+tcp_head_size, payload_len, malicious_host, host_len);
	}
	// http response
	else if (ntohs(tcp_header->th_sport) == PORT_HTTP) {
		printf("HTTP Response\n");
	}
	return 1;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	printf("entering callback\n");

	printf("call print_pkt\n");
	u_int32_t id = print_pkt(nfa);
	printf("call check_url\n");
	u_int32_t permission = check_url(nfa);
	/*
	 argument : uint32_t verdict
	 #define NF_DROP 0
	 #define NF_ACCEPT 1
	*/
	return nfq_set_verdict(qh, id, permission, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	// input parsing
	if (argc != 2) {
		fprintf(stderr, "USAGE : sudo ./netfilter-test [malicious host name]\n");
		return 1;
	}
	if (strlen(argv[1]) >= 256) {
		fprintf(stderr, "Host name (argv[1]) is too long... \n");
		fprintf(stderr, "Host name length is less than 255 \n");
		return 1;
	}

	// fill malicious host name
	unsigned char host_name[256];
	memcpy(host_name, argv[1], strlen(argv[1]));
	malicious_host = host_name;

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

