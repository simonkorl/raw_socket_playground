#include "ether_tools.h"
#include <event2/event.h>

#include <event2/event.h>

void recv_cb_func(evutil_socket_t fd, short what, void *arg) {
    const char *data = arg;
    printf("Got an event on socket %d:%s%s%s%s [%s]\n",
        (int) fd,
        (what&EV_TIMEOUT) ? " timeout" : "",
        (what&EV_READ)    ? " read" : "",
        (what&EV_WRITE)   ? " write" : "",
        (what&EV_SIGNAL)  ? " signal" : "",
        data);

    if(what & EV_READ) {
        char buffer[2048] = {0};
        int ret_raw = recvfrom(fd, buffer, 2048, 0, NULL, NULL);
        /* Check to see if the packet contains at least
        * complete Ethernet (14), IP (20) and TCP/UDP
        * (8) headers.
        */
        if (ret_raw < 42) {
            fprintf(stderr,"--------return--\n");
            return;
        }
        unsigned char *iphead, *ethhead;
        ethhead = buffer;
        // fprintf(stderr,"Source MAC address: "
        //         "%02x:%02x:%02x:%02x:%02x:%02x\n",
        //         ethhead[0],ethhead[1],ethhead[2],
        //         ethhead[3],ethhead[4],ethhead[5]);
        // fprintf(stderr,"Destination MAC address: "
        //         "%02x:%02x:%02x:%02x:%02x:%02x\n",
        //         ethhead[6],ethhead[7],ethhead[8],
        //         ethhead[9],ethhead[10],ethhead[11]);

        iphead = buffer+14; /* Skip Ethernet header */
        if (*iphead==0x45) { /* Double check for IPv4
                            * and no options present */
            int src_port = (iphead[20]<<8)+iphead[21];
            int dst_port = (iphead[22]<<8)+iphead[23];
            if(src_port == 5566 && dst_port == 5567) {
                fprintf(stderr, "A special ipv4 packets from the writing callback!!\n");
                fprintf(stderr,"Source host %d.%d.%d.%d\n",
                    iphead[12],iphead[13],
                    iphead[14],iphead[15]);
                fprintf(stderr,"Dest host %d.%d.%d.%d\n",
                    iphead[16],iphead[17],
                    iphead[18],iphead[19]);
                fprintf(stderr,"Source,Dest ports %d,%d\n",
                    (iphead[20]<<8)+iphead[21],
                    (iphead[22]<<8)+iphead[23]);
                fprintf(stderr,"Layer-4 protocol %d\n",iphead[9]);
                for (size_t i = 0; i < ret_raw-14; i++) {
                    fprintf(stderr, "%x",iphead[i]);
                }
                fprintf(stderr, "\n========##==========\n");
            }
            printf("\n==================\n");
        }
    }
}
struct write_arg {
    const char* words;
    int fd;
};



void write_cb_func(evutil_socket_t fd, short what, void *arg) {
    struct write_arg *data = arg;
    printf("Got an event on socket %d:%s%s%s%s [%s]\n",
        (int) fd,
        (what&EV_TIMEOUT) ? " timeout" : "",
        (what&EV_READ)    ? " read" : "",
        (what&EV_WRITE)   ? " write" : "",
        (what&EV_SIGNAL)  ? " signal" : "",
        data->words);
    printf("writing fd: %d\n", data->fd);
    // unsigned char to[6];
    // mac_aton("00:00:00:00:00:00",to);
    uint8_t udp_data[1024], ip_data[2048];
    int udp_len = create_udp_packet(5566, 5567, "hello", sizeof("hello"), udp_data, 1024);
    int ipv4_len = create_ipv4_packet("127.0.0.1", "127.0.0.1", IPPROTO_UDP, udp_data, udp_len, ip_data, 2048);
    send_ether_name("lo", "lo", ETH_P_IP, ip_data, ipv4_len, data->fd);
    printf("finish writing\n");
}

void main_loop(evutil_socket_t fd1, evutil_socket_t fd2) {
        struct event *ev1, *ev2;
        struct timeval five_seconds = {5,0};
        struct timeval two_seconds = {2, 0};
        struct write_arg write_data = {"Writing event", fd2};
        struct event_base *base = event_base_new();

        /* The caller has already set up fd1, fd2 somehow, and make them
           nonblocking. */

        ev1 = event_new(base, fd1, EV_TIMEOUT|EV_READ|EV_PERSIST, recv_cb_func,
           (char*)"Reading event");
        ev2 = event_new(base, -1, EV_TIMEOUT|EV_WRITE|EV_PERSIST, write_cb_func,
            &write_data);

        event_add(ev1, &five_seconds);
        event_add(ev2, &two_seconds);
        event_base_dispatch(base);
}
int main() {
    int socket = CreateRawSocket(ETH_P_ALL);
    if(socket <= 0) {
        perror("Create raw socket failed");
        return -1;
    }
    // bind interface to localhost
    if(BindRawSocketToInterface("lo", socket, ETH_P_ALL)) {
        perror("bind interface error");
        return -1;
    }
    setnonblock(socket);
    printf("bind finish\n");

    main_loop(socket, socket);
    return 0;
}