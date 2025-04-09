#pragma once

#include "ip.h"
#include "mac.h"
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include "ethhdr.h"
#include "arphdr.h"

// Function to retrieve the attacker's IP and MAC address dynamically
void getHostInfo(const char* interfaceName, Ip* ip, Mac* mac);

// Function to retrieve the MAC address of a target IP by sending an ARP request
Mac getMac(pcap_t* pcap, Ip attackerIp, Mac attackerMac, Ip targetIp);
