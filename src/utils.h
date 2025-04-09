#pragma once

#include "ip.h"
#include "mac.h"
#include <pcap.h>

// Function to retrieve the attacker's IP and MAC address dynamically
void getHostInfo(const char* interfaceName, Ip* ip, Mac* mac);

// Function to retrieve the MAC address of a target IP by sending an ARP request
Mac getMac(pcap_t* pcap, Ip attackerIp, Mac attackerMac, Ip targetIp);
