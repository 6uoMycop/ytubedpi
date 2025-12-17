#ifndef __YT_CLIENT_H
#define __YT_CLIENT_H

#ifndef YT_MAX_FILTERS
#define YT_MAX_FILTERS 1
#endif // !YT_MAX_FILTERS

#ifndef YT_MAX_PACKET_SIZE
#define YT_MAX_PACKET_SIZE 9016
#endif // !YT_MAX_PACKET_SIZE

#define yt_dbg_dump(len, buf) \
        do { \
            for (int __i = 0; __i < (len); __i++) printf("%02X ", (unsigned char)((buf)[__i])); \
            printf("\n"); \
        } while (0)

#endif // __YT_CLIENT_H
