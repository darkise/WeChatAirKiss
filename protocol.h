#ifndef AIRKISS_PROTOCOL_H
#define AIRKISS_PROTOCOL_H
#include <stdint.h>

enum {
    AIRKISS_INIT = 0,
    AIRKISS_LEADING,
    AIRKISS_LEADING_FIN,
    AIRKISS_MAGICCODE,
    AIRKISS_MAGIC_FIN,
    AIRKISS_PREFIXCODE,
    AIRKISS_PREFIX_FIN,
    AIRKISS_SEQUENCE,
    AIRKISS_DONE
};

int airkiss_init();
void airkiss_deinit();
void airkiss_reset();

int airkiss_input(uint8_t* bssid, uint8_t* sa, uint16_t input);

int airkiss_state();
int airkiss_pwd(char* pwd);
int airkiss_ssid(char* ssid);
uint8_t airkiss_randnum();

int airkiss_answer();

uint8_t CRC8(uint8_t* message, uint8_t len);

#endif //AIRKISS_PROTOCOL_H
