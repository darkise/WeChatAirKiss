#include "protocol.h"
#include <stdint.h>

uint8_t CRC8(uint8_t* message, uint8_t len)
{
    uint8_t crc = 0;
    uint8_t i;

    //uint8_t tlen = len;
    //printf("CRC8(");
    while (len--)
    {
        //printf("%02x ", *message);
        crc ^= *message++;
        for (i = 0; i < 8; i++)
        {
            if (crc & 0x01)
                crc = (crc >> 1) ^ 0x8c;
            else
                crc >>= 1;
        }
    }
    //printf(", %u)\n", tlen);

    return crc;
}
