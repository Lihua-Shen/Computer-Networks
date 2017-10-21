/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  check_packet_len(len, ETH_HDR);
  
  /* Check if the packet is ARP or IP packet */
  if (ethertype(packet) == ethertype_arp) 
    { handle_arp_packet(sr, packet, len, interface); }
  else if (ethertype(packet) == ethertype_ip) 
    { handle_ip_packet(sr, packet, len, interface); }

}/* end sr_ForwardPacket */

/* This function handles ARP packets */
void handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{ 
  check_packet_len(len, ARP_PACKET);

  /* Verify the length of ARP packet */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
      printf("Packet is way too short \n");
      return;
  }

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Get the interface through which the packet arrived */
  struct sr_if *intf = sr_get_interface(sr, interface);
  
  /* Verify the ARP packet is destined to the router */
  if (intf->ip != arp_hdr->ar_tip) {
      printf("The ARP packet is not destined to the router\n");
      return;  
  }
  
  /* In the case of an ARP request */
  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
      /* Make a copy of the packet */
      uint8_t *arpPacket = malloc(len);
      memcpy(arpPacket, packet, len);
      
      /* Update all the fields of the packet */

      /* Update Ethernet header */
      sr_ethernet_hdr_t *arpPacket_ethernet_hdr = (sr_ethernet_hdr_t *)arpPacket;
      memcpy(arpPacket_ethernet_hdr->ether_dhost, arpPacket_ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(arpPacket_ethernet_hdr->ether_shost, intf->addr, ETHER_ADDR_LEN);

      /* Update ARP header */
      sr_arp_hdr_t *arpPacket_arp_hdr = (sr_arp_hdr_t *)(arpPacket + sizeof(sr_ethernet_hdr_t));
      arpPacket_arp_hdr->ar_op = htons(arp_op_reply);                   
      memcpy(arpPacket_arp_hdr->ar_sha, intf->addr, ETHER_ADDR_LEN);     
      arpPacket_arp_hdr->ar_sip = intf->ip;                               
      memcpy(arpPacket_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN); 
      arpPacket_arp_hdr->ar_tip = arp_hdr->ar_sip;

      /* Send ARP reply */
      sr_send_packet(sr, arpPacket, len, interface);
      printf("Send ARP reply\n");
      free(arpPacket);                     
  }

  /* In the case of an ARP reply */
  if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
      /* Insert entry in ARP cache and get the corresponding ARP request */
      struct sr_arpreq *arpRequest = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

      if (arpRequest) {
          struct sr_packet *outstandingPacket = arpRequest->packets;
          
          /* Send all the outstanding packets in the ARP queue */
          while (outstandingPacket) {
              struct sr_if *outgoingIntf = sr_get_interface(sr, outstandingPacket->iface);

              if (outgoingIntf) {
                  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(outstandingPacket->buf);
                  memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                  memcpy(ethernet_hdr->ether_shost, outgoingIntf->addr, ETHER_ADDR_LEN);

                  sr_send_packet(sr, outstandingPacket->buf, outstandingPacket->len, outstandingPacket->iface);
              }

              outstandingPacket = outstandingPacket->next;
          }

          sr_arpreq_destroy(&sr->cache, arpRequest);
      }
      return;
  }
  return;
}

/* This function handles IP packets */
void handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* Get Ethernet header */
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t *) packet; 

  /* Get IP header */
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Get ARP Cache */
  struct sr_arpcache *sr_cache = &sr->cache;

  check_packet_len(len, IP_PACKET);

  if (validate_ip_checksum(ip_hdr)) {
      printf("IP Checksum doesn't match \n");
      return;
  }

  /* Check to see if the IP packet is destined to the router */
  struct sr_if *intf = sr_get_interface_given_ip(sr, ip_hdr->ip_dst);
  /* If the IP packet is destined to the router */
  if (intf) {
      uint8_t ip_p = ip_protocol((uint8_t *)ip_hdr); 
      /* If it is ICMP */
      if (ip_p == ip_protocol_icmp) {
          /* Get ICMP header */
          sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          check_packet_len(len, ICMP_PACKET);

          if (validate_icmp_checksum(icmp_hdr, ICMP_PACKET, len)) {
              printf("ICMP Checksum doesn't match \n");
              return;
          }

          /* If it is ICMP echo request, then generate ICMP echo reply */
          if (icmp_hdr->icmp_type == icmp_echo_request) {
              send_echo_reply(sr, packet, len, interface);
          }
      }
      /* If it is TCP or UDP, then generate ICMP port unreachable */
      else if (ip_p == ip_protocol_tcp || ip_p == ip_protocol_udp) {
          send_icmp_error_msg(sr, packet, len, icmp_dest_unreachable, icmp_port_unreachable);
      }
  } 

  /* If the IP packet is not destined to the router */
  else {
      /* Check TTL. If TTL=1, send ICMP time exceeded */
      if (ip_hdr->ip_ttl == 1)
      {
          send_icmp_error_msg(sr, packet, len, icmp_time_exceeded, (uint8_t)0);
          return;
      }

      /* Look up next-hop address by doing a longest prefix match on the routing table using the packet's destination address */
      struct sr_rt *out_port = longest_prefix_match(sr, ip_hdr->ip_dst);

      /* If the packet's destination address exists in the routing table */
      if (out_port) {
          /* Reduce TTL */
          ip_hdr->ip_ttl--;

          /* Update checksum */
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        
          /* Determine outgoing interface */
          struct sr_if *out_iface = sr_get_interface(sr, out_port->interface);

          /* Check ARP cache using next-hop ip address */
          struct sr_arpentry * arp_entry = sr_arpcache_lookup(sr_cache, out_port->gw.s_addr); 

          /* If the lookup returned an ARP entry, then modify the Ethernet source and destination values and send the packet to next hop */
          if (arp_entry){
              memcpy(eth_hdr->ether_shost, out_iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
              memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(unsigned char)*ETHER_ADDR_LEN);
              sr_send_packet (sr, packet, len, out_iface->name); 
              return;
          } 

          /* If there is no match in our ARP cache */
          else { 
              /* Add the ARP request to the ARP request queue */              
              struct sr_arpreq * req = sr_arpcache_queuereq(sr_cache, ip_hdr->ip_dst, packet, len, out_iface->name);
              handle_arpreq(req, sr);
              return;
          }
      } 

      /* If the packet's destination address does not exist in the routing table, send ICMP destination net unreachable */
      else {
          send_icmp_error_msg(sr, packet, len, icmp_dest_unreachable, icmp_dest_net_unreachable);
          return;
      }
  }
  return;
}

/* This function verifies the length of packet */
void check_packet_len(unsigned int len, int type) {
    int min_len = 0;
    switch (type) {
        case ETH_HDR:
            min_len = sizeof (sr_ethernet_hdr_t);
            break; 
        case ARP_PACKET:
            min_len = sizeof (sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            break; 
        case IP_PACKET:
            min_len = sizeof (sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
            break; 
        case ICMP_PACKET:
            min_len = sizeof (sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof (sr_icmp_hdr_t);
            break; 
        case ICMP_TYPE3_PACKET:
            min_len = sizeof (sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof (sr_icmp_t3_hdr_t);
            break; 
    }

    if (len < min_len) {
        printf( "Packet is way too short \n");
    }
    return;
}

/* This function sends ICMP echo reply */
void send_echo_reply (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    struct sr_arpcache *sr_cache = &sr->cache;

    /* Modify ethernet header */
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

    /* Modify IP header */ 
    uint32_t src_ip = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = src_ip;
    memset(&(ip_hdr->ip_sum), 0, sizeof(uint16_t));
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Modify ICMP header  */
    icmp_hdr->icmp_type = icmp_echo_reply;
    icmp_hdr->icmp_code = (uint8_t)0;
    memset(&(icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    struct sr_arpentry * arp_entry = sr_arpcache_lookup (sr_cache, ip_hdr->ip_dst);
    if (arp_entry) {
      sr_send_packet (sr, packet, len, interface);
    } else {
        struct sr_arpreq * req = sr_arpcache_queuereq(sr_cache, ip_hdr->ip_dst, packet, len, interface);
        handle_arpreq(req, sr);
    }
}

/* This function sends an ICMP message */
void send_icmp_error_msg(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code)
{
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    struct sr_arpcache *sr_cache = &sr->cache;

    /* Get longest matching prefix for source */
    struct sr_rt *route = longest_prefix_match(sr, ip_hdr->ip_src);
    if (!route)
    {
        printf("Cannot find routing table entry \n");
        return;
    }

    /* Get the sending interface */
    struct sr_if *sending_intf = sr_get_interface(sr, route->interface);

    /* Calculate new packet length */
    unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *new_packet = malloc(new_len);

    /* Sanity Check */
    assert(new_packet);

    /* Need to construct new headers for type 3 */
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)new_packet;
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));

    /* Init ethernet header */
    memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
    memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = htons(ethertype_ip);

    /* Init IP header */
    new_ip_hdr->ip_v = 4;
    new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4; /* ip_hl is in words */
    new_ip_hdr->ip_tos = 0;
    new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_ip_hdr->ip_id = htons(0);
    new_ip_hdr->ip_off = htons(IP_DF);
    new_ip_hdr->ip_ttl = 255;
    new_ip_hdr->ip_p = ip_protocol_icmp;

    new_ip_hdr->ip_src = code == icmp_port_unreachable ? ip_hdr->ip_dst : sending_intf->ip;
    new_ip_hdr->ip_dst = ip_hdr->ip_src;

    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

    /* Init ICMP header */
    new_icmp_hdr->icmp_type = type;
    new_icmp_hdr->icmp_code = code;
    new_icmp_hdr->unused = 0;
    new_icmp_hdr->next_mtu = 0; /* May need additional code here to handle code 4 */
    memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

    new_icmp_hdr->icmp_sum = 0;
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    struct sr_arpentry *cached = sr_arpcache_lookup(&sr->cache, route->gw.s_addr);

    if (cached) {
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)new_packet;
        memcpy(eth_hdr->ether_shost, sending_intf->addr, ETHER_ADDR_LEN); /* Source: MAC address from the interface that sent it */
        memcpy(eth_hdr->ether_dhost, cached->mac, ETHER_ADDR_LEN);     /* Dest: MAC address from ARP cache entry */

        sr_send_packet(sr, new_packet, new_len, sending_intf->name);
        free(cached);
    }
    else {
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, route->gw.s_addr, new_packet, new_len, sending_intf->name);
        handle_arpreq(sr, req);
    }
    free(new_packet);
    return;
}        
