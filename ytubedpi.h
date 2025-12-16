#ifndef __YT_CLIENT_H
#define __YT_CLIENT_H

#ifndef W2E_MAX_FILTERS
#define W2E_MAX_FILTERS 1
#endif // !W2E_MAX_FILTERS

#ifndef W2E_MAX_PACKET_SIZE
#define W2E_MAX_PACKET_SIZE 9016
#endif // !W2E_MAX_PACKET_SIZE

#define yt_dbg_dump(len, buf) \
        do { \
            for (int __i = 0; __i < (len); __i++) printf("%02X ", (unsigned char)((buf)[__i])); \
            printf("\n"); \
        } while (0)

#endif // __YT_CLIENT_H
