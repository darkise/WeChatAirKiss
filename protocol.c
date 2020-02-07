#include "protocol.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>

#define AIRKISS_LEADING_SIZE  4
#define AIRKISS_SEQUENCE_SIZE 6

typedef struct airkiss_ctx {
    struct airkiss_ctx *next;
    // Index
    uint8_t key[12]; // BSSID+SA

    // parsing state
    int state;
    int substate;

    // 前导数据
    uint16_t basecode;
    // 临时数据
    uint16_t tmp[AIRKISS_SEQUENCE_SIZE];
    uint8_t tmplen;

    // Magic code
    uint8_t datalen;
    uint8_t ssidcrc;
    uint8_t seqc;
    uint8_t seqs[32];

    // Prefix Code
    uint8_t pwdlength;
    uint8_t pwdlencrc;

    // Sequence header
    uint8_t seqcrc;
    uint8_t sequence;
    // Data
    uint8_t crcdata[6];
    uint8_t datard;
    // Result
    uint8_t data[32+1+64]; // password+RandomChar+ssid
} airkiss_ctx;


static airkiss_ctx *_header = NULL, *_tail = NULL;

/*
 * AirKiss 流程
0. 获取当前无线环境中所有非隐蔽AP的ssid，rssi以及信道(非必要的过程,但是可以节省配网时间)
1. 切换信道
2. 等待前导数据，确定长度基数,前导数据为4个连续的数组成，可重复多次
3. 如果接收前导数据超时，则跳转到1，否则跳转到4
4. 接收magic code字段，可重复多次
magic code 字段定义
               | 高5位  | 低4位           |
第  1 个 9bits | 0x0    | length(high)    |
第  2 个 9bits | 0x1    | length(low)     |
第  3 个 9bits | 0x2    | ssid crc8(high) |
第  4 个 9bits | 0x3    | ssid crc8(low)  |
5. 接收prefix code字段
               | 高5位  | 低4位              |
第  1 个 9bits | 0x4    | pwd length(high)   |
第  2 个 9bits | 0x5    | pwd length(low)    |
第  3 个 9bits | 0x6    | pwd len crc8(high) |
第  4 个 9bits | 0x7    | pwd len crc8(low)  |
6. 接收数据Sequence，数据sequence包括两部分: sequence header和data
Sequence header字段
               | 8 | 7 | 6 ~ 0
第  1 个 9bits | 0 | 1 | sequnece crc8(low 7bits) |
第  2 个 9bits | 0 | 1 | sequnece index           |
data 字段
               | 8 | 7 ~ 0
第  1 个 9bits | 1 | data |
第  2 个 9bits | 1 | data |
第  3 个 9bits | 1 | data |
第  4 个 9bits | 1 | data |
*/

int airkiss_sequence(airkiss_ctx* ak, uint16_t d);

int airkiss_init()
{
    airkiss_ctx* p = _header;
    while (p) {
        airkiss_ctx* t = p->next;
        free (p);
        p = t;
    }
    _header = _tail = NULL;
    return 0;
}

void airkiss_deinit()
{
    airkiss_ctx* p = _header;
    while (p) {
        airkiss_ctx* t = p->next;
        free (p);
        p = t;
    }
    _header = _tail = NULL;
}

void airkiss_reset()
{
    airkiss_ctx* p = _header;
    while (p) {
        airkiss_ctx* t = p->next;
        memset(p, 0, sizeof(airkiss_ctx));
        p->next = t;
        p = p->next;
    }
}

int _airkiss_input(airkiss_ctx* ak, uint16_t input)
{
    if (!ak)
        return -1;
    uint16_t d;
    uint8_t idx, td;

    if (ak->state >= AIRKISS_LEADING_FIN &&
            input < ak->basecode) {
        printf("Invaild data, reset airkiss state\n");
        ak->state = AIRKISS_INIT;
        ak->basecode = 0;
    }
    switch(ak->state) {
    case AIRKISS_INIT:
        ak->tmp[0] = input;
        ak->tmplen = 1;
        printf("AIRKISS_LEADING\n");
        ak->state = AIRKISS_LEADING;
        break;

    case AIRKISS_LEADING:
        if (ak->tmplen < AIRKISS_LEADING_SIZE) {
            ak->tmp[ak->tmplen] = input;
            ak->tmplen++;
        }
        else {
            // 数据移动
            ak->tmp[0] = ak->tmp[1];
            ak->tmp[1] = ak->tmp[2];
            ak->tmp[2] = ak->tmp[3];
            ak->tmp[3] = input;
        }
        if (ak->tmplen == AIRKISS_LEADING_SIZE) {
            if (ak->tmp[0] + 1 == ak->tmp[1] &&
                    ak->tmp[1] + 1 == ak->tmp[2] &&
                    ak->tmp[2] + 1 == ak->tmp[3]) {
                ak->basecode = ak->tmp[0] - 1;
                ak->tmplen = 0;
                ak->state = AIRKISS_LEADING_FIN;
                ak->datalen = 0;
                ak->ssidcrc = 0;
                ak->substate = 0;
                printf("AIRKISS_MAGICCODE, base code: %u\n", ak->basecode);
            }
        }
        break;

    case AIRKISS_LEADING_FIN:
        // 等待前导数据结束，结束判断：数据大于4
        d = input - ak->basecode;
        if (d > 4)
            ak->state = AIRKISS_MAGICCODE;
        break;

    case AIRKISS_MAGICCODE:
        d = input - ak->basecode;
        idx = (d >> 4) & 0x1f;
        td = (uint8_t)(d & 0x000f);
        switch (idx) {
        case 0x00:
            ak->datalen |= (td << 4) & 0xf0;
            ak->substate |= 0x01;
            break;
        case 0x01:
            ak->datalen |= td;
            ak->substate |= 0x02;
            break;
        case 0x02:
            ak->ssidcrc |= (td << 4) & 0xf0;
            ak->substate |= 0x04;
            break;
        case 0x03:
            ak->ssidcrc |= td;
            ak->substate |= 0x08;
            break;
        default:
            return -1;
        }
        if (0x0f == ak->substate) {
            ak->state = AIRKISS_MAGIC_FIN;
            ak->pwdlencrc = 0;
            ak->pwdlength = 0;
            ak->substate = 0;

            //
            memset(ak->seqs, 0, sizeof(ak->seqs));
            uint8_t dlen = ak->datalen;
            dlen += 3;
            dlen >>= 2;
            ak->seqc = dlen - 1;
            for (uint8_t i = 0; i < dlen; i++) {
                ak->seqs[i] = 1;
            }
            printf("AIRKISS_PREFIXCODE, data length: %u, sequence count %u\n", ak->datalen, dlen);
        }
        break;

    case AIRKISS_MAGIC_FIN:
        // 等待Magic结束，结束判断：数据的前5bit大于 3
        d = input - ak->basecode;
        idx = (d >> 4) & 0x1f;
        if (idx > 0x03)
            ak->state = AIRKISS_PREFIXCODE;
        break;

    case AIRKISS_PREFIXCODE:
        d = input - ak->basecode;
        idx = (d >> 4) & 0x1f;
        td = (uint8_t)(d & 0x000f);
        if (idx < 0x04) // 依然是Magic数据，丢弃
            break;
        switch (idx) {
        case 0x04:
            ak->pwdlength |= (td << 4) & 0xf0;
            ak->substate |= 0x01;
            break;
        case 0x05:
            ak->pwdlength |= td;
            ak->substate |= 0x02;
            break;
        case 0x06:
            ak->pwdlencrc |= (td << 4) & 0xf0;
            ak->substate |= 0x04;
            break;
        case 0x07:
            ak->pwdlencrc |= td;
            ak->substate |= 0x08;
            break;
        default:
            return -1;
        }
        if (0x0f == ak->substate) {
            ak->state = AIRKISS_PREFIX_FIN;
            ak->tmplen = 0;
            ak->substate = 0;
            printf("AIRKISS_SEQUENCE, pwd length: %u\n", ak->pwdlength);
        }
        break;

    case AIRKISS_PREFIX_FIN:
        // 等待PREFIX结束，结束判断：数据的前5bit大于 3
        d = input - ak->basecode;
        idx = (d >> 4) & 0x1f;
        if (idx > 0x07) {
            ak->state = AIRKISS_SEQUENCE;
            ak->tmplen = 0;
        }
        else
            break;

    case AIRKISS_SEQUENCE:
        d = input - ak->basecode;
        airkiss_sequence(ak, d);
        break;

    case AIRKISS_DONE:
        break;
    default:
        return -1;
    }

    return 0;
}

int airkiss_input(uint8_t* bssid, uint8_t* sa, uint16_t input)
{
    //
    uint8_t zeros[12] = {0};
    uint8_t key[12];
    memcpy(key, bssid, 6);
    memcpy(key+6, sa, 6);

    /*printf("input: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, input [%u]\n",
           key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11], input);*/

    // 查找列表
    airkiss_ctx* p = _header;
    while (p) {
        if (memcmp(p->key, key, 12) == 0 // 命中
                || memcmp(p->key, zeros, 12) == 0) { // 空节点
            break;
        }
        p = p->next;
    }
    if (!p) {
        p = (airkiss_ctx*) malloc(sizeof(airkiss_ctx));
        memset(p, 0, sizeof(airkiss_ctx));
        // Insert
        if (_tail) {
            _tail->next = p;
            _tail = p;
        }
        else {
            _header = _tail = p;
        }
    }
    memcpy(p->key, key, 12);
    return _airkiss_input(p, input);
}

int airkiss_state()
{
    int state = 0;
    airkiss_ctx* p = _header;
    while (p) {
        if (p->state > state)
            state = p->state;
        p = p->next;
    }
    return state;
}

int airkiss_sequence(airkiss_ctx* ak, uint16_t d)
{
    uint8_t* data = ak->crcdata + 2;
    uint8_t idx;

    //printf("input %u, tmplen %u, \n", d, ak->tmplen);
    idx = (d >> 7) & 0xff;
    if (0x01 == idx) { // sequence header
        if (0 == ak->tmplen) {
            // Sequence crc
            ak->seqcrc = (uint8_t)(d & 0x007f);
            ak->tmplen++;
            ak->sequence = 0;
            return 0;
        }
        else if (1 == ak->tmplen) {
            // Sequence number
            ak->sequence = (uint8_t)(d & 0x007f);
            if (ak->sequence > ak->seqc) {
                ak->tmplen = 0;
                ak->sequence = 0;
                return -1;
            }
            ak->crcdata[ak->tmplen] = ak->sequence;
            ak->tmplen++;
            return 0;
        }
        if (ak->tmplen >= 2) {
            ak->tmplen = 0;
            return -1;
        }
    }
    else if (0x02 == (0x02 & idx)) {
        // Data
        if (ak->tmplen < 2) {
            ak->tmplen = 0;
            return -1;
        }
        ak->crcdata[ak->tmplen++] = (uint8_t)(d & 0x00ff);
    }

    // 判断数据是否足够
    uint8_t dlen = ak->tmplen - 2;
    if (dlen == 4 ||
            (ak->seqc == ak->sequence && dlen == (ak->datalen & 0x03))) {
        ak->tmplen = 0;
        // 数据足够
        // 如果这个包已经有则不必再次解析
        if (0 == ak->seqs[ak->sequence]) {
            printf("Sequence number %u has set\n", ak->sequence);
            return 0;
        }
        // CRC 校验
        uint8_t crc = CRC8(ak->crcdata+1, dlen+1);
        if ((crc & 0x7f) != ak->seqcrc) {
            printf("CRC8 error, length %u, %02x|%02x\n", dlen, ak->seqcrc, crc);
            return -1;
        }

        // 数据拷贝
        for (int i = 0; i < dlen; i++) {
            ak->data[ak->sequence*4+i] = data[i];
            printf("%u: %02x\n", ak->sequence*4+i, data[i]);
        }
        ak->seqs[ak->sequence] = 0;
        // 结束判断
        uint8_t res = 0;
        for (uint8_t i = 0; i <= ak->seqc; i++) {
            res |= ak->seqs[i];
        }
        if (!res) {
            //printf("DONE! ssid: %s, pwd: %.*s\n", ak->data+ak->pwdlength+1, ak->pwdlength, ak->data);
            ak->state = AIRKISS_DONE;
        }
    }

    return 0;
}

int _airkiss_pwd(airkiss_ctx* p, char* pwd)
{
    if (AIRKISS_DONE == p->state ||
            (AIRKISS_SEQUENCE == p->state &&
                p->datard >= p->pwdlength)) {
        memcpy(pwd, p->data, p->pwdlength);
        pwd[p->pwdlength] = '\0';

        return (int)p->pwdlength;
    }
    return 0;
}

int airkiss_pwd(char* pwd)
{
    if (!pwd) return -1;

    airkiss_ctx* p = _header;
    while (p) {
        if (AIRKISS_DONE == p->state ||
                (AIRKISS_SEQUENCE == p->state &&
                    p->datard >= p->pwdlength)) {

            memcpy(pwd, p->data, p->pwdlength);
            pwd[p->pwdlength] = '\0';

            return (int)p->pwdlength;
        }
        p = p->next;
    }
    return 0;
}

int airkiss_ssid(char* ssid)
{
    if (!ssid) return -1;

    airkiss_ctx* p = _header;
    while (p) {
        if (AIRKISS_DONE == p->state) {
            int len = p->datalen - p->pwdlength - 1;
            memcpy(ssid, &p->data[p->pwdlength+1], len);
            ssid[len] = '\0';

            return len;
        }
        p = p->next;
    }
    return 0;
}

uint8_t airkiss_randnum()
{
    airkiss_ctx* p = _header;
    while (p) {
        if (AIRKISS_DONE == p->state) {
            return p->data[p->pwdlength];
        }
        p = p->next;
    }
    return 0xff;
}

static ssize_t udp_broadcast(uint8_t random, int port)
{
#if 0
    FILE* fp = fopen("/proc/net/route", "r");
    if (fp) {
        char buf[512] = {0};
        fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
        printf("Route table: %s\n", buf);
    }
#endif

    int fd;
    int enabled = 1;
    int err;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_BROADCAST;
    addr.sin_port = htons(port);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf ("Error to create socket, reason: %s", strerror(errno));
        return 1;
    }

    err = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *) &enabled, sizeof(enabled));
    if(err == -1) {
        close(fd);
        return 1;
    }

    ssize_t r = sendto(fd, (unsigned char *)&random, 1, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr));
    close(fd);

    return r;
}

int airkiss_answer()
{
    // 回应 AIRKISS
    // 连接后根据airkiss协议, 向10000端口广播random值通知发送端即可完成配置.
    uint8_t randnum = airkiss_randnum();

#define ms *1000
    for (int i = 0; i < 50; i++) {
        ssize_t r = udp_broadcast(randnum, 10000);
        printf("SO_BROADCAST %d, %ld, %s\n", i, r, r<0?strerror(errno):"Success");
        usleep(200 ms);
    }
#undef ms
    return 0;
}
