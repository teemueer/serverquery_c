#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct Info {
        char address[22];
        int protocol;
        char hostname[256];
        char map[32];
        char gamedir[32];
        char gamedesc[256];
        short appid;
        int numplayers;
        int maxplayers;
        int numbots;
        int servertype;
        int os;
        int password;
        int secure;

        char link[256];
        char downloadlink[256];
        long version;
        long size;
        int gametype;
        int gamedll;
};

void get_byte(int *dst, char src, int *idx)
{
    *dst = src;
    *idx += 1;
}


void get_short(short *dst, char *src, int *idx)
{
    *dst = *(short*)&src[*idx];
    *idx += 2;
}

void get_long(long *dst, char *src, int *idx)
{
        *dst = *(long*)&src[*idx];
        *idx += 4;
}

void get_string(char dst[], char src[], int *idx)
{
    strcpy(dst, &src[*idx]);
    *idx += strlen(dst)+1;
}

int get_sock(char *ip, int port)
{
        int sock;
        struct sockaddr_in server;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv,sizeof(struct timeval));

    server.sin_addr.s_addr = inet_addr(ip);
        server.sin_family = AF_INET;
        server.sin_port = htons(port);

        connect(sock, (struct sockaddr *)&server, sizeof(server));
        return sock;
}

struct Info server_query(char ip[], int port)
{
    struct Info info;
    memset(info.hostname, '\0', sizeof(info.hostname));

    int sock = get_sock(ip, port);

    char msg[] = "\xFF\xFF\xFF\xFF\x54Source Engine Query";
        send(sock, msg, 25, 0);

    char buf[2048];
        int res_len = recv(sock, buf, 2048, 0);

    if (res_len < 4)
        return info;

        int header = buf[4];
    int ismod;
    int idx = 5;
    if (header == '\x49') {
        get_byte(&info.protocol, buf[idx], &idx);
        get_string(info.hostname, buf, &idx);
        get_string(info.map, buf, &idx);
        get_string(info.gamedir, buf, &idx);
        get_string(info.gamedesc, buf, &idx);
        get_short(&info.appid, buf, &idx);
        get_byte(&info.numplayers, buf[idx], &idx);
        get_byte(&info.maxplayers, buf[idx], &idx);
        get_byte(&info.numbots, buf[idx], &idx);
        get_byte(&info.servertype, buf[idx], &idx);
        get_byte(&info.os, buf[idx], &idx);
        get_byte(&info.password, buf[idx], &idx);
        get_byte(&info.secure, buf[idx], &idx);
    } else if (header == '\x6d') {
                get_string(info.address, buf, &idx);
                get_string(info.hostname, buf, &idx);
                get_string(info.map, buf, &idx);
                get_string(info.gamedir, buf, &idx);
                get_string(info.gamedesc, buf, &idx);
                get_byte(&info.numplayers, buf[idx], &idx);
                get_byte(&info.maxplayers, buf[idx], &idx);
        get_byte(&info.protocol, buf[idx], &idx);
                get_byte(&info.servertype, buf[idx], &idx);
                get_byte(&info.os, buf[idx], &idx);
                get_byte(&info.password, buf[idx], &idx);
        get_byte(&ismod, buf[idx], &idx);
        if (ismod) {
            get_string(info.link, buf, &idx);
            get_string(info.downloadlink, buf, &idx);
            idx += 1; // null
            get_long(&info.version, buf, &idx);
            get_long(&info.size, buf, &idx);
            get_byte(&info.gametype, buf[idx], &idx);
            get_byte(&info.gamedll, buf[idx], &idx);
        }
                get_byte(&info.secure, buf[idx], &idx);
        get_byte(&info.numbots, buf[idx], &idx);
    }
    sprintf(info.address, "%s:%d", ip, port);
    close(sock);
    return info;
}

void main(int argc, char **argv)
{
    if (argc < 2) {
        puts("Pass filters as an argument.");
        return;
    }

    int sock = get_sock("208.64.200.52", 27011);
    
    char msg[256];
    //char first[] = "0.0.0.0:0";
    char last[] = "0.0.0.0:0";
    char filters[256];
    strcpy(filters, argv[1]);
    int last_len;

    msg[0] = 0x31;
    msg[1] = 0xff;

    last_len = strlen(last) + 1;
    strncpy(&msg[2], last, last_len);
    strcpy(&msg[2+last_len], filters);
    int msg_len = 2 + last_len + strlen(filters);

    send(sock, msg, msg_len, 0);

    char res[2048];
    int res_len = recv(sock, res, 2048, 0);

    char ip[16];
    int port;

    int idx = 6;
    while (idx < res_len) {
        sprintf(ip, "%d.%d.%d.%d",
                (unsigned char)res[idx],
                (unsigned char)res[idx+1],
                (unsigned char)res[idx+2],
                (unsigned char)res[idx+3]);
        port = ntohs((res[idx+4] | res[idx+5] << 8));
        
        if (strcmp(ip, "0.0.0.0")) {
            struct Info info = server_query(ip, port);
            if (strlen(info.hostname)) {
                printf("[%s] %s - %s - %d/%d - %s\n",
                    info.gamedir, info.hostname, info.map,
                    info.numplayers, info.maxplayers,
                    info.address);
            }
        }
        idx += 6;
    }

    close(sock);
}
