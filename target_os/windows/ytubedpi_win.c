// ytubedpi.cpp: определяет точку входа для приложения.
//

#include "ytubedpi_win.h"
#include "windivert.h"
#include <stdio.h>
#include <signal.h>
#include <stdint.h>


/**
 * Have to be global because they are passed to signal handler.
 */
static HANDLE g_filters[YT_MAX_FILTERS];
static int g_filter_num = 0;

static volatile int loop_stop = 0;


/**
 * Check if running as Administrator.
 */
static BOOL _yt__is_admin()
{
    BOOL fIsElevated = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        printf("Failed to get Process Token: %d\n", GetLastError());
        goto cleanup; /* if Failed, we treat as False */
    }


    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
    {
        printf("Failed to get Token Information: %d\n", GetLastError());
        goto cleanup; /* if Failed, we treat as False */
    }

    fIsElevated = elevation.TokenIsElevated;

cleanup:
    if (hToken)
    {
        CloseHandle(hToken);
        hToken = NULL;
    }
    return fIsElevated;
}


/**
 * WinDivert initialization.
 */
static HANDLE _yt__init(char* filter, UINT64 flags)
{
    LPTSTR errormessage = NULL;
    DWORD errorcode = 0;

    printf("Init...\n");

    filter = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);

    if (filter != INVALID_HANDLE_VALUE)
    {
        printf("Init OK\n");
        return filter;
    }

    errorcode = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorcode, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&errormessage, 0, NULL);

    printf("Error opening filter: %d %s\n", errorcode, errormessage);

    LocalFree(errormessage);

    if (errorcode == 2)
    {
        printf("The driver files WinDivert32.sys or WinDivert64.sys were not found.\n");
    }
    else if (errorcode == 654)
    {
        printf(
            "An incompatible version of the WinDivert driver is currently loaded.\n"
            "Please unload it with the following commands ran as administrator:\n\n"
            "sc stop windivert\n"
            "sc delete windivert\n"
            "sc stop windivert14"
            "sc delete windivert14\n");
    }
    else if (errorcode == 1275)
    {
        printf(
            "This error occurs for various reasons, including:\n"
            "the WinDivert driver is blocked by security software; or\n"
            "you are using a virtualization environment that does not support drivers.\n");
    }
    else if (errorcode == 1753)
    {
        printf(
            "This error occurs when the Base Filtering Engine service has been disabled.\n"
            "Enable Base Filtering Engine service.\n");
    }
    else if (errorcode == 577)
    {
        printf(
            "Could not load driver due to invalid digital signature.\n"
            "Windows Server 2016 systems must have secure boot disabled to be \n"
            "able to load WinDivert driver.\n"
            "Windows 7 systems must be up-to-date or at least have KB3033929 installed.\n"
            "https://www.microsoft.com/en-us/download/details.aspx?id=46078\n\n"
            "WARNING! If you see this error on Windows 7, it means your system is horribly "
            "outdated and SHOULD NOT BE USED TO ACCESS THE INTERNET!\n"
            "Most probably, you don't have security patches installed and anyone in you LAN or "
            "public Wi-Fi network can get full access to your computer (MS17-010 and others).\n"
            "You should install updates IMMEDIATELY.\n");
    }

    return NULL;
}


/**
 * WinDivert deinitialization.
 */
static int _yt__deinit(HANDLE handle)
{
    if (handle)
    {
        WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(handle);
        return TRUE;
    }
    return FALSE;
}


/**
 * WinDivert deinitialization of all filters.
 */
static void _yt__deinit_all(HANDLE* filters, int filter_num)
{
    for (int i = 0; i < filter_num; i++)
    {
        _yt__deinit(filters[i]);
    }
}


/**
 * SIGINT handler.
 */
static void _yt__sigint_handler(int sig)
{
    (void)sig;

    loop_stop = 1;
    Sleep(1000);
    _yt__deinit_all(g_filters, g_filter_num);
    exit(EXIT_SUCCESS);
}


/**
 * Send WinDivert packet.
 */
static BOOL _yt__pkt_send(HANDLE handle, const VOID* pPacket, UINT packetLen, UINT* pSendLen, const WINDIVERT_ADDRESS* pAddr)
{
    DWORD errorcode = 0;

    if (!WinDivertSend(handle, pPacket, packetLen, pSendLen, pAddr))
    {
        errorcode = GetLastError();
        printf("Error sending unmodified packet! 0x%X\n", errorcode);

        switch (errorcode)
        {
        case 1232:
        {
            printf(
                "ERROR_HOST_UNREACHABLE: This error occurs when an impostor packet "
                "(with pAddr->Impostor set to 1) is injected and the ip.TTL or ipv6. "
                "HopLimit field goes to zero. This is a defense of \"last resort\" against "
                "infinite loops caused by impostor packets. \n");
            break;
        }
        default:
        {
            printf("Unexpected error 0x%X\n", errorcode);
            break;
        }
        }
        return FALSE;
    }

    return TRUE;
}


/**
 * Client's main packet processing loop.
 */
static void _yt__main_loop(HANDLE w_filter)
{
    DWORD					errorcode = 0;

    UINT					len_recv;

    WINDIVERT_ADDRESS		addr;
    UINT8					proto;

    PWINDIVERT_IPHDR		hdr_ip;
    PWINDIVERT_TCPHDR		hdr_tcp;

    PVOID					data;
    UINT					len_data;

    static uint8_t			pkt[YT_MAX_PACKET_SIZE] = { 0 };


    printf("Main loop operating\n");

    while (!loop_stop)
    {
        /**
         * Receive packet.
         */
        if (WinDivertRecv(w_filter, pkt, sizeof(pkt), &len_recv, &addr))
        {
            hdr_ip = (PWINDIVERT_IPHDR)NULL;
            hdr_tcp = (PWINDIVERT_TCPHDR)NULL;

            /**
             * Parse packet.
             */
            if (WinDivertHelperParsePacket(
                pkt,
                len_recv,
                &hdr_ip,
                NULL, //&hdr_ipv6,
                &proto,
                NULL, //&hdr_icmp,
                NULL, //&hdr_icmpv6,
                &hdr_tcp,
                NULL, //&hdr_udp,
                &data,
                &len_data,
                NULL,
                NULL))
            {
                /**
                 * Modification
                 */
                // @todo
#if 0
                //yt_dbg_dump(len_data, (uint8_t *)data);
                for (int i = 0; i < 8; i++)
                {
                    printf("%c", ((uint8_t *)data)[31 * 4 + i]);
                }
                printf("\n");

                if (memcmp(&(((uint8_t*)data)[31 * 4 + 1]), "i.ytimg", 7) == 0)
                {
                    printf("+\n");
                    //((uint8_t*)data)[31 * 4 + 1] = "I";
                }
#endif // 0
                /** Send packet */
                _yt__pkt_send(w_filter, pkt, len_recv, NULL, &addr);
            }
        }
        else
        {
            errorcode = GetLastError();
            printf("Error receiving packet! 0x%X\n", errorcode);

            switch (errorcode)
            {
            case 122:
            {
                printf("ERROR_INSUFFICIENT_BUFFER: The captured packet is larger than the pPacket buffer\n");
                break;
            }
            case 232:
            {
                printf("ERROR_NO_DATA: The handle has been shutdown using WinDivertShutdown() and the packet queue is empty.\n");
                break;
            }
            default:
            {
                printf("Unexpected error 0x%X\n", errorcode);
                break;
            }
            }
        }
    }
}



int main(int argc, char* argv[])
{
    HANDLE w_filter = NULL;

    if (!_yt__is_admin())
    {
        printf("You need to run W2E Client as Administrator. Press Enter to terminate.\n");
        (void)getchar();
        exit(1);
    }

    /**
     * SIGINT handler.
     */
    signal(SIGINT, _yt__sigint_handler);

    /**
     * Filters initialization.
     */

    /**
     * tcp.DstPort == 443   | HTTPS
     * tcp.Payload[0] == 22 | TLS Handshake
     * tcp.Payload[5] ==  1 | TLS Client Hello
     * 
     * www.youtube.com
     * tcp.Payload32[31] == 0x0f777777 | server name length, "www"
     * tcp.Payload32[32] == 0x2e796f75 | ".you"
     * 
     * i.ytimg.com
     * tcp.Payload32[31] == 0x0b692e79 | server name length, "i.y"
     * tcp.Payload32[32] == 0x74696d67 | "timg"
     * 
     * yt3.ggpht.com
     * tcp.Payload32[31] == 0x0d797433 | server name length, "yt3"
     * tcp.Payload32[32] == 0x2e676770 | ".ggp"
     */
    g_filters[g_filter_num] = _yt__init(
        "outbound and !loopback and (tcp.DstPort == 443 and tcp.Payload[0] == 22 and tcp.Payload[5] == 1"
        " and ("
           " (tcp.Payload32[31] == 0x0f777777 and tcp.Payload32[32] == 0x2e796f75)"
        " or (tcp.Payload32[31] == 0x0b692e79 and tcp.Payload32[32] == 0x74696d67)"
        " or (tcp.Payload32[31] == 0x0d797433 and tcp.Payload32[32] == 0x2e676770)"
        "))",
        0);
    w_filter = g_filters[g_filter_num];
    g_filter_num++;

    if (!w_filter)
    {
        printf("Filter init error\n");
        return 1;
    }


    /**
     * Start.
     */
    _yt__main_loop(w_filter);

    return 0;
}
