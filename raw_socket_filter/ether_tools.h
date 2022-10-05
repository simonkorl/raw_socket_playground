#ifndef _ETHER_H_
#define _ETHER_H_
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include <linux/filter.h>
#include <sys/socket.h>

#define MAX_ETHERNET_DATA_SIZE 1500
#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_DST_ADDR_OFFSET 0
#define ETHERNET_SRC_ADDR_OFFSET 6
#define ETHERNET_TYPE_OFFSET 12
#define ETHERNET_DATA_OFFSET 14

#define MAC_BYTES 6

#define IS_HEX(c) ( \
    (c) >= '0' && (c) <= '9' || \
    (c) >= 'a' && (c) <= 'f' || \
    (c) >= 'A' && (c) <= 'F' \
)

#define HEX(c) ( \
    ((c) >= 'a') ? ((c) - 'a' + 10) : ( \
        ((c) >= 'A') ? ((c) - 'A' + 10) : ((c) - '0') \
    ) \
)

/**
 * @description:
 * @param {int} protocol_to_sniff
 *ETH_P_IP 0x0800 只接收发往本机mac的ip类型的数据帧
 *ETH_P_ARP 0x0806 只接受发往本机mac的arp类型的数据帧
 *ETH_P_RARP 0x08035 只接受发往本机mac的rarp类型的数据帧
 *ETH_P_ALL 0x3 接收发往本机mac的所有类型ip arp rarp的数据帧,
 *接收从本机发出的所有类型的数据帧.(混杂模式打开的情况下,会接收到非发往本地mac的数据帧)
 * @return {*}
 */
int CreateRawSocket(int protocol_to_sniff) {
    int rawsock;

    if ((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff))) ==
        -1) {
        perror("Error creating raw socket: ");
        exit(-1);
    }

    return rawsock;
}
/**
 * @description:
 * @param {char} *device
 * the device e.g. eth0
 * @param {int} rawsock
 * @param {int} protocol
 * 与CreateRawSocket的参数一致
 * @return {*}
 */
int BindRawSocketToInterface(char *device, int rawsock, int protocol) {
    struct sockaddr_ll sll;
    struct ifreq ifr;

    bzero(&sll, sizeof(sll));
    bzero(&ifr, sizeof(ifr));

    /* First Get the Interface Index  */

    strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
    if ((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1) {
        fprintf(stderr,"Error getting Interface index !\n");
        exit(-1);
    }

    /* Bind our raw socket to this interface */

    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(protocol);

    if ((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll))) == -1) {
        perror("Error binding raw socket to interface\n");
        exit(-1);
    }

    return 0;
}
int setnonblock(int fd) {
    int old_option = fcntl(fd, F_GETFL);
    int new_option = old_option | O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}
/**
 *  Convert readable MAC address to binary format.
 *
 *  Arguments
 *      a: buffer for readable format, like "08:00:27:c8:04:83".
 *
 *      n: buffer for binary format, 6 bytes at least.
 *
 *  Returns
 *      0 if success, -1 if error.
 **/
int mac_aton(const char *a, unsigned char *n) {
    int matches = sscanf(a, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", n, n+1, n+2,
                         n+3, n+4, n+5);

    return (6 == matches ? 0 : -1);
}

/**
 *  Fetch MAC address of given iface.
 *
 *  Arguments
 *      iface: name of given iface.
 *
 *      mac: buffer for binary MAC address, 6 bytes at least.
 *
 *      s: socket for ioctl, optional.
 *
 *  Returns
 *      0 if success, -1 if error.
 **/
int fetch_iface_mac(char const *iface, unsigned char *mac, int s) {
    // value to return, 0 for success, -1 for error
    int value_to_return = -1;

    // create socket if needed(s is not given)
    bool create_socket = (s < 0);
    if (create_socket) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (-1 == s) {
            return value_to_return;
        }
    }

    // fill iface name to struct ifreq
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, 15);

    // call ioctl to get hardware address
    int ret = ioctl(s, SIOCGIFHWADDR, &ifr);
    if (-1 == ret) {
        goto cleanup;
    }

    // copy MAC address to given buffer
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_BYTES);

    // success, set return value to 0
    value_to_return = 0;

cleanup:
    // close socket if created here
    if (create_socket) {
        close(s);
    }

    return value_to_return;
}


/**
 *  Fetch index of given iface.
 *
 *  Arguments
 *      iface: name of given iface.
 *
 *      s: socket for ioctl, optional.
 *
 *  Returns
 *      Iface index(which is greater than 0) if success, -1 if error.
 **/
int fetch_iface_index(char const *iface, int s) {
    // iface index to return, -1 means error
    int if_index = -1;

    // create socket if needed(s is not given)
    bool create_socket = (s < 0);
    if (create_socket) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (-1 == s) {
            return if_index;
        }
    }

    // fill iface name to struct ifreq
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, 15);

    // call ioctl system call to fetch iface index
    int ret = ioctl(s, SIOCGIFINDEX, &ifr);
    if (-1 == ret) {
        goto cleanup;
    }

    if_index = ifr.ifr_ifindex;

cleanup:
    // close socket if created here
    if (create_socket) {
        close(s);
    }

    return if_index;
}

/**
 * Bind socket with given iface.
 *
 *  Arguments
 *      s: given socket.
 *
 *      iface: name of given iface.
 *
 *  Returns
 *      0 if success, -1 if error.
 **/
int bind_iface(int s, char const *iface) {
    // fetch iface index
    int if_index = fetch_iface_index(iface, s);
    if (-1 == if_index) {
        return -1;
    }

    // fill iface index to struct sockaddr_ll for binding
    struct sockaddr_ll sll;
    bzero(&sll, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_index;
    sll.sll_pkttype = PACKET_HOST;

    // call bind system call to bind socket with iface
    int ret = bind(s, (struct sockaddr *)&sll, sizeof(sll));
    if (-1 == ret) {
        return -1;
    }

    return 0;
}

/**
 *  Send data through given iface by ethernet protocol, using raw socket.
 *
 *  Arguments
 *      iface: name of iface for sending.
 *
 *      to: destination MAC address, in binary format.
 *
 *      type: protocol type.
 *
 *      data: data to send, ends with '\0'.
 *
 *      s: socket for ioctl, optional.
 *
 *  Returns
 *      0 if success, -1 if error.
 **/
int send_ether(char const *iface, unsigned char const *to, short type,
        char const *data,int data_len, int s) {
    // value to return, 0 for success, -1 for error
    int value_to_return = -1;

    // create socket if needed(s is not given)
    bool create_socket = (s < 0);
    if (create_socket) {
        s = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
        if (-1 == s) {
            return value_to_return;
        }
    }

    // bind socket with iface
    int ret = bind_iface(s, iface);
    if (-1 == ret) {
        goto cleanup;
    }

    // fetch MAC address of given iface, which is the source address
    unsigned char fr[6];
    ret = fetch_iface_mac(iface, fr, s);
    if (-1 == ret) {
        goto cleanup;
    }

    // construct ethernet frame, which can be 1514 bytes at most
    unsigned char frame[1514];

    // fill destination MAC address
    memcpy(frame + ETHERNET_DST_ADDR_OFFSET, to, MAC_BYTES);

    // fill source MAC address
    memcpy(frame + ETHERNET_SRC_ADDR_OFFSET, fr, MAC_BYTES);

    // fill type
    *((short *)(frame + ETHERNET_TYPE_OFFSET)) = htons(type);

    // truncate if data is to longstrlen(data);
    int data_size = data_len;
    if (data_size > MAX_ETHERNET_DATA_SIZE) {
        data_size = MAX_ETHERNET_DATA_SIZE;
    }

    // fill data
    memcpy(frame + ETHERNET_DATA_OFFSET, data, data_size);

    int frame_size = ETHERNET_HEADER_SIZE + data_size;

    ret = sendto(s, frame, frame_size, 0, NULL, 0);
    if (-1 == ret) {
        goto cleanup;
    }

    // set return value to 0 if success
    value_to_return = 0;

cleanup:
    // close socket if created here
    if (create_socket) {
        close(s);
    }

    return value_to_return;
}

/**
 * @brief Create a udp packet and write in buf
 * 
 * @author MC
 * @param src_port 
 * @param dst_port 
 * @param data: should be network endian
 * @param data_len: in bytes
 * @param buf 
 * @param max_buf_len 
 * @return int : return the length of data in bytes
 */
int create_udp_packet(int src_port, int dst_port, 
        unsigned char* data, int data_len, 
        unsigned char* buf, int max_buf_len) {
    int length = data_len + 8;
    if(max_buf_len < length) {
        // insuffient buffer
        return -1;
    }
    buf[0] = src_port >> 8;
    buf[1] = src_port & 0xff;
    buf[2] = dst_port >> 8;
    buf[3] = dst_port & 0xff;
    // length
    buf[4] = length >> 8;
    buf[5] = length & 0xff;
    // checksum
    buf[6] = 0x00;
    buf[7] = 0x00;
    // data
    memcpy(buf + 8, data, data_len);
    return length;
}
/**
 * @brief Create a ipv4 packet to buf
 * 
 * @author MC
 * @param src_ip 
 * @param dst_ip 
 * @param type: in netinet/ip.h, IPPROTO_TCP, IPPROTO_UDP
 * @param data 
 * @param data_len 
 * @param buf 
 * @param max_buf_len 
 * @return int 
 */
int create_ipv4_packet(const char* src_ip, const char* dst_ip, short type,
    unsigned char* data, int data_len, 
    unsigned char* buf, int max_buf_len) {
    int length = data_len + 20;
    if(max_buf_len < length) {
        // insuffient buffer
        return -1;
    }
    struct iphdr hdr;
    hdr.version = 4;
    hdr.ihl = 5;
    hdr.tos = 0;
    hdr.tot_len = htons(length);
    hdr.id = 0;
    hdr.frag_off = 0;
    hdr.ttl = 255;
    hdr.protocol = type;
    hdr.check = 0x0;
    hdr.saddr = inet_addr(src_ip);
    hdr.daddr = inet_addr(dst_ip);

    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + 20, data, data_len);
    return length;
}

/**
 * @brief Send data through given iface by ethernet protocol, using raw socket.
 * 
 * @author MC
 * @param iface: name of iface for sending.
 * @param to: name of iface for destination.
 * @param type: ether protocol type in netinet/ether.h. ETH_P_IP, ETH_P_IPV6
 * @param data: data to send, ends with '\0'.
 * @param s: socket for ioctl, optional.
 * @return int:   0 if success, -1 if error.
 **/
int send_ether_name(char const *iface, char const *ifaceto, short type,
        char const *data,int data_len, int s) {
    // value to return, 0 for success, -1 for error
    int value_to_return = -1;

    // create socket if needed(s is not given)
    bool create_socket = (s < 0);
    if (create_socket) {
        s = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
        if (-1 == s) {
            return value_to_return;
        }
    }

    // bind socket with iface
    int ret = bind_iface(s, iface);
    if (-1 == ret) {
        goto cleanup;
    }

    // fetch MAC address of given iface, which is the source address
    unsigned char fr[6];
    ret = fetch_iface_mac(iface, fr, s);
    if (-1 == ret) {
        goto cleanup;
    }

    // fetch MAC address of given iface to, which is the dst address
    unsigned char to[6];
    ret = fetch_iface_mac(ifaceto, to, -1);
    if (-1 == ret) {
        goto cleanup;
    } 

    // construct ethernet frame, which can be 1514 bytes at most
    unsigned char frame[1514];

    // fill destination MAC address
    memcpy(frame + ETHERNET_DST_ADDR_OFFSET, to, MAC_BYTES);

    // fill source MAC address
    memcpy(frame + ETHERNET_SRC_ADDR_OFFSET, fr, MAC_BYTES);

    // fill type
    *((short *)(frame + ETHERNET_TYPE_OFFSET)) = htons(type);

    // truncate if data is to longstrlen(data);
    int data_size = data_len;
    if (data_size > MAX_ETHERNET_DATA_SIZE) {
        data_size = MAX_ETHERNET_DATA_SIZE;
    }

    // fill data
    memcpy(frame + ETHERNET_DATA_OFFSET, data, data_size);

    int frame_size = ETHERNET_HEADER_SIZE + data_size;

    ret = sendto(s, frame, frame_size, 0, NULL, 0);
    if (-1 == ret) {
        goto cleanup;
    }

    // set return value to 0 if success
    value_to_return = 0;

cleanup:
    // close socket if created here
    if (create_socket) {
        close(s);
    }

    return value_to_return;
}

/**
 * @brief Create a sock filter object
 * 
 * @param max_len: the maximum number of filter codes in the filter. Recommend > 6
 * @return struct sock_fprog*: the filter pointer, need to call free_sock_filter to release space
 */
struct sock_fprog* create_sock_filter(int max_len) {
    struct sock_fprog *filter = malloc(sizeof(struct sock_fprog));
    filter->filter = malloc(sizeof(struct sock_filter) * max_len);
    return filter;
}

/**
 * @brief Free filter object from create_sock_filter
 * 
 * @param filter: the filter point created by create_sock_filter
 */
void free_sock_filter(struct sock_fprog *filter) {
    free(filter->filter);
    free(filter);
}

/**
 * @brief Set up a filter that only allows packets not from a given mac address
 * 
 * @param mac_str: the string of mac like 01:02:03:04:05:06
 * @param output: the sock_filter pointer to store the result
 * @param max_size: the maximum size 
 * @return int: return the length of filter if succeed, else return -1
 */
int set_not_src_mac_filter(const char *mac_str, struct sock_filter *output, int max_size) {
    uint8_t mac[10];
    mac_aton(mac_str, mac);
    // tcpdump not ether src 01:02:03:04:05:06 -dd 
    struct sock_filter code[] = {
        { 0x20, 0, 0, 0x00000008 },
        { 0x15, 0, 3, ntohl(*(unsigned int *)(mac + 2)) },
        { 0x28, 0, 0, 0x00000006 },
        { 0x15, 0, 1, ntohs(*(unsigned short *) mac)},
        { 0x6, 0, 0, 0x00000000 },
        { 0x6, 0, 0, 0x00040000 },
    };
    if(sizeof(code) >= max_size) {
        fprintf(stderr, "set filter output size too small, require %ld bytes\n", sizeof(code));
        return -1;
    }
    memcpy(output, code, sizeof(code));
    return sizeof(code) / sizeof(struct sock_filter);
}

/**
 * @brief Set up a filter that only allows packets targets a given mac address
 * 
 * @param mac_str: the string of mac like 01:02:03:04:05:06
 * @param output: the sock_filter pointer to store the result
 * @param max_size: the maximum size 
 * @return int: return the length of filter if succeed, else return -1
 */
int set_dst_mac_filter(const char *mac_str, struct sock_filter *output, int max_size) {
    uint8_t mac[10];
    mac_aton(mac_str, mac);
    // tcpdump not ether src 01:02:03:04:05:06 -dd 
    struct sock_filter code[] = {
        { 0x20, 0, 0, 0x00000002 },
        { 0x15, 0, 3, ntohl(*(unsigned int *)(mac + 2)) },
        { 0x28, 0, 0, 0x00000000 },
        { 0x15, 0, 1, ntohs(*(unsigned short *) mac) },
        { 0x6, 0, 0, 0x00040000 },
        { 0x6, 0, 0, 0x00000000 },
    };
    if(sizeof(code) >= max_size) {
        fprintf(stderr, "set filter output size too small, require %ld bytes\n", sizeof(code));
        return -1;
    }
    memcpy(output, code, sizeof(code));
    return sizeof(code) / sizeof(struct sock_filter);
}

/**
 * @brief Set the sock opt filter object
 * 
 * @param fd 
 * @param filter 
 * @return int 
 */
int set_sock_opt_filter(int fd, struct sock_fprog* filter) {
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, filter, sizeof(*filter));
}

/**
 * @brief Set up the 'not src mac' filter for a fd using mac string
 * 
 * @param fd 
 * @param mac_str 
 * @return struct sock_fprog*: the filter object, need to be freed using free_sock_filter
 */
struct sock_fprog* set_sock_not_src_mac_filter(int fd, const char *mac_str) {
    struct sock_fprog *filter = create_sock_filter(12);
    filter->len = set_not_src_mac_filter(mac_str, 
        filter->filter, sizeof(struct sock_filter) * 12);
    if(set_sock_opt_filter(fd, filter) < 0) {
        free_sock_filter(filter);
        perror("set sock opt filter error");
        return NULL;
    }
    return filter;
}

//========================================
// tests
//========================================
void test_filter() {
    struct sock_fprog *filter = create_sock_filter(12);
    struct sock_filter *filter_code = filter->filter;
    filter->len = set_not_src_mac_filter("01:02:03:04:05:06", filter_code, 12 * sizeof(struct sock_filter));
    for(int i = 0;i < filter->len; ++i) {
        fprintf(stderr, "%d code: %x %x %x %x\n", i, 
        filter_code[i].code, filter_code[i].jt, filter_code[i].jf, filter_code[i].k);
    }
    free_sock_filter(filter);
    return;
}
#endif // _ETHER_H_