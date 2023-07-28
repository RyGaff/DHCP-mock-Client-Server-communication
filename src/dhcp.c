#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>


#include "dhcp.h"
/* This work complies with the JMU Honor Code.
 * References and Acknowledgments: I received no outside
 * help with this programming assignment. */

void
dump_packet (uint8_t *ptr, size_t size)
{
  size_t index = 0;
  while (index < size)
    {
      fprintf (stderr, " %02" PRIx8, ptr[index++]);
      if (index % 32 == 0)
        fprintf (stderr, "\n");
      else if (index % 16 == 0)
        fprintf (stderr, "  ");
      else if (index % 8 == 0)
        fprintf (stderr, " .");
    }
  if (index % 32 != 0)
    fprintf (stderr, "\n");
  fprintf (stderr, "\n");
}

/*Fill up the mesage struct given the information from the file*/
msg_t
populateMessage(FILE *fp){
  msg_t msg;
  fread(&msg, sizeof(msg_t), 1, fp); 
  return msg;
}

void
printOutput(msg_t msg, char *lch){
printf("Op Code (op) = %d %s\n", msg.op, getOp(msg.op));
printf("Hardware Type (htype) = %d %s\n", msg.htype, getHardware(msg.htype));
printf("Hardware Address Length (hlen) = %d\n", msg.hlen);
printf("Hops (hops) = %d\n", msg.hops);
// htonl() Takes big endian and turns it into little endian
printf("Transaction ID (xid) = %d (0x%x)\n",htonl(msg.xid), htonl(msg.xid));

printf("Seconds (secs) = ");
printTime(htons(msg.secs));
printf("Flags (flags) = %d\n", msg.flags);
printf("Client IP Address (ciaddr) = %s\n", inet_ntoa(msg.ciaddr));
printf("Your IP Address (yiaddr) = %s\n", inet_ntoa(msg.yiaddr));
printf("Server IP Address (siaddr) = %s\n", inet_ntoa(msg.siaddr));
printf("Relay IP Address (giaddr) = %s\n", inet_ntoa(msg.giaddr));
printf("Client Ethernet Address (chaddr) = ");
//Loop to print out chaddr array
// if (!lch){
if (msg.hlen > 16 && !lch){
  for (int i = 0; i < msg.hlen*2; i++){
    if (msg.chaddr[i]) printf("%c", msg.chaddr[i]);
    else printf("0");
  } 
} else {
  for (int i = 0; i < msg.hlen; i++){
    printf("%02hhx", msg.chaddr[i]);
  } 
} 

printf("\n");
}

char*
getOp(uint type){
  switch (type)
  {
  case BOOTREQUEST:
    return "[BOOTREQUEST]";
  case BOOTREPLY:
    return "[BOOTREPLY]";
  
  default:
    break;
  }

  return "ERROR";
}

char*
getHardware(uint type){
  switch (type)
  {
  case ETH:
    return "[Ethernet (10Mb)]";
  case IEEE802:
    return "[IEEE 802 Networks]";
  case ARCNET:
    return "[ARCNET]";
  case FRAME_RELAY:
    return "[Frame Relay]";
  case FIBRE:
    return "[Fibre Channel]";
  case ATM:
    return "[Asynchronous Transmission Mode (ATM)]";
  default:
    break;
  }
  return "ERROR";
}

bool
checkCookie(FILE *fp){
  // Seek to where cookie, read 32 bits (uint32), / 4 bytes
  //rewind(fp);
  fseek(fp, sizeof(msg_t), SEEK_SET);
  uint32_t test;
  fread(&test, sizeof(uint32_t), 1, fp);
  return htonl (test) == MAGIC_COOKIE;
}

void
printOptions(uint8_t tagOct){
  switch (tagOct)
  {
  case DHCPDISCOVER:
    printf("Message Type = DHCP Discover\n");
    break;
  case DHCPOFFER:
    printf("Message Type = DHCP Offer\n");
    break;
  case DHCPREQUEST:
    printf("Message Type = DHCP Request\n");
    break;
  case DHCPDECLINE:
    printf("Message Type = DHCP Decline\n");
    break;
  case DHCPACK:
    printf("Message Type = DHCP ACK\n");
    break;
  case DHCPNAK:
    printf("Message Type = DHCP NAK\n");
    break;
  case DHCPRELEASE:
    printf("Message Type = DHCP Release\n");
    break;
  default:
    printf("Message Type = INVAL|NotImplemented, Val = %d\n", tagOct);
    break;
  }
}

void
printTime(uint32_t secs){
  int days = secs / (60 * 60 * 24);
  secs -= days * (60 * 60 * 24);
  int hours = secs / (60 * 60);
  secs -= hours * (60 * 60);
  int mins = secs / 60;
  secs -= mins * 60;
  printf("%d Days, %d:%02d:%02d\n", days, hours, mins, secs);
}

void
leaseTime(uint8_t *octets, uint32_t len, int i){
  uint32_t secs = 0;
  uint32_t shift = 8;
  for (int j = 1; j < len + 1; j++){
  secs = secs << shift;
  if (octets[j + i] == 0xff){
    secs |= 0x00;
  } else {
     secs |= octets[j + i];
  }

  }
  printf("IP Address Lease Time = ");
  printTime(secs);
}

void
servIden(uint8_t *octets, uint32_t len, int i){

  for (int j = 0; j < len; j++){
      printf("%d", octets[i + j]);
    if (j != len -1){
      printf(".");
      }
  }
    printf("\n");
}

void 
options(uint8_t *octets, bool print_id_after){
      
      int id_loc = 0;
      bool set = false;  
      uint8_t type = octets[2] & 0xF;
      printf("Magic Cookie = [OK]\n");
      printOptions(type);
      // Read Octets until ff is found
      int i = 3;
      while (octets[i] != 0xff){
        //Get the type and len
        uint32_t code = octets[i];
        uint32_t len = octets[i + 1];
        
        switch (code)
        {
        case 51: // IP Lease Time code 
          i += 1;
          leaseTime(octets, len, i);
          if (set){
            printf("Server Identifier = ");
            servIden(octets, len, id_loc);
          }
          i += len;
          break;
        case 54: // Server Identifier
         
          len = octets[i + 1];
          i += 2;
          if (print_id_after){
            set = true;
            id_loc = i;
          } else {
            printf("Server Identifier = ");
            servIden(octets, len, i);
          }

          i+= len;
          break;
        case 50:
          len = octets[i + 1];
          if (len <= 1){
            puts("Len is less than or eqal to 1 ERROR");
          } else{
            printf("Request = ");
            i+=2;
            servIden(octets, len, i);
          }
          i+=len;
          break;
        
        default:
          i++;
          break;
        }
      }
}