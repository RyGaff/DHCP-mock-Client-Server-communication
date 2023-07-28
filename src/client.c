#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>

#include "dhcp.h"
#include "format.h"
#include "port_utils.h"
/* This work complies with the JMU Honor Code.
 * References and Acknowledgments: I received no outside
 * help with this programming assignment. */

msg_t msg;
uint8_t octets[MAX_DHCP_LENGTH];
uint8_t _req[4] = {0x7f,0x00,0x00,0x02};
uint8_t _servId[4]= {0x7f,0x00,0x00,0x01};
char *lch = NULL;
bool p_flag = false;
int ffloc = 0;

//Could also do a char and then read two characters as a buffer

static bool get_args (int argc, char **argv);
static void update_hlen();
static uint64_t swapEndian(long long num, int len);
static void fillocts(long dhcp_type);

int
main (int argc, char **argv)
{
  printf("------------------------------------------------------\n");
  printf("BOOTP Options\n");
  printf("------------------------------------------------------\n");
  char *dc = "010203040506";
  long def_chaddr = 1108152157446;
  long swapped = swapEndian(def_chaddr, strlen(dc)-2);
  uint32_t cookie = MAGIC_COOKIE;

  in_addr_t def_add = 0x00000000;
  //Build the default message 
  // memset(&msg, 0, sizeof(msg_t));
  msg.op = 1;
  msg.htype = 1; // default ETH
  msg.hlen = 6; 
  msg.hops = 0; 
  msg.xid = htonl(42); 
  msg.secs = 0;
  msg.flags = 0;
  //Not sure if addrs are correct
  msg.ciaddr.s_addr = def_add;
  msg.yiaddr.s_addr = def_add;
  msg.siaddr.s_addr = def_add;
  msg.giaddr.s_addr = def_add;
  memcpy(&msg.chaddr, &swapped, sizeof(msg.chaddr));

  memset(octets, 0, sizeof(octets));
  //Discover is default
  fillocts(DHCPDISCOVER);
  get_args(argc, argv);

  printOutput(msg, NULL);
  printf("------------------------------------------------------\n");
  printf("DHCP Options\n");
  printf("------------------------------------------------------\n");
  options(octets, false);

  if (p_flag){
    //init
    int socketfd = -1;
    char *local = "127.0.0.1";
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    //o2 is the second octets array that contains both the bootp and dhcp msg
    uint8_t o2[sizeof(msg_t) + MAX_DHCP_LENGTH];
    memset(o2, 0, sizeof(o2));

    //Attempt to create a TCP IPv4 socket
    if ((socketfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0){
      printf("socket no good\n");
      return -1;
    }

    struct timeval timeout = { 5, 0 };
    setsockopt (socketfd, SOL_SOCKET, SO_RCVTIMEO, (const void *) &timeout,
                sizeof (timeout));

  
    //Fill server infro
    server.sin_family = AF_INET;
    server.sin_port = htons(strtol(get_port(), 0, 10));
    server.sin_addr.s_addr = inet_addr(local);

    socklen_t len = sizeof(server);
    bind (socketfd, (struct sockaddr *) &server, len);


    //Need to swap endian of the cookie
    uint32_t snack = swapEndian(cookie, 6);
    //fill our second message
    memcpy(o2, &msg, sizeof(msg_t));
    memcpy(o2 + sizeof(msg), &snack, sizeof(MAGIC_COOKIE));
    memcpy(o2 + sizeof(msg) + sizeof(MAGIC_COOKIE), octets, ffloc);
    //val is the ending location of ff, we only want to send up to that point
    unsigned int val = ffloc + sizeof(msg) + sizeof(MAGIC_COOKIE);

    //Send the msg + dhcp (o2) options to the server
    
    ssize_t bytes = -1;
    if((bytes = sendto(socketfd, &o2, val, 0,
         (struct sockaddr*)&server, len)) < 0){
        printf("Unable to send message\n");
        return -1;
    }

    // char addr_buffer[INET_ADDRSTRLEN];
    // inet_ntop (AF_INET, &server.sin_addr, addr_buffer, sizeof (addr_buffer));
    // printf ("Sent %zd bytes to %s\n", bytes, addr_buffer);

    uint8_t buffer[MAX_DHCP_LENGTH];
    memset(buffer, 0, sizeof(buffer));
    if ((bytes = recvfrom(socketfd, buffer, MAX_DHCP_LENGTH - 1, 0, (struct sockaddr *) &server, &len)) > 0){
      // printf("bytes = %zd\n",  bytes);
    }
    // Building on the code that you have already implemented to create a packet,
    //  you will start by sending a DHCP Discover message just as you did before. 

    //  Next, you will continue the protocol by receiving a message from 
    //  the server (should be a DHCP Offer), then sending a DHCP Request, 
      //get yiaddr from the buffer
        //put in the dhcp requested field
    if (msg.xid != 0){
       if (octets[2] != DHCPNAK) {
          printf("++++++++++++++++\nCLIENT RECEIVED:\n");
          //prints out the recv client, also refills octets with new dhcp data
          recvClient(buffer, socketfd, server, bytes);
       }


      //send request
      memset(o2, 0, sizeof(o2));
      memcpy(o2, &msg, sizeof(msg_t));
      memcpy(o2 + sizeof(msg), &snack, sizeof(MAGIC_COOKIE));
      memcpy(o2 + sizeof(msg) + sizeof(MAGIC_COOKIE), octets, ffloc);
      val = ffloc + sizeof(msg) + sizeof(MAGIC_COOKIE);
      o2[val] = 0xff;
      //Go throuhgh dchp options, update identifier, 
      //0 out yiaddr
      // printf("********CLIENT SENDING**********\n");
      if((bytes = sendto(socketfd, &o2, val+1, 0,
         (struct sockaddr*)&server, len)) < 0){
        printf("Unable to send message\n");
        return -1;
        }

      if (octets[2] != DHCPACK){
        if (octets[2] != DHCPNAK) printf("++++++++++++++++\n");
       printf("------------------------------------------------------\n");
       printf("BOOTP Options\n");
       printf("------------------------------------------------------\n");
       printOutput(msg, NULL);

       printf("------------------------------------------------------\n");
       printf("DHCP Options\n");
       printf("------------------------------------------------------\n");
       if (octets[2] != DHCPNAK){
        options(octets,false);
       }
    }

      if ((bytes = recvfrom(socketfd, buffer, MAX_DHCP_LENGTH - 1, 0, (struct sockaddr *) &server, &len)) > 0){
      // printf("bytes = %zd\n",  bytes);
    }
      //recv ack
     if (octets[2] != DHCPNAK) printf("++++++++++++++++\nCLIENT RECEIVED:\n");
      recvClient(buffer, socketfd, server, bytes);
      if (octets[2] == DHCPNAK) options(octets, false);
      printf("++++++++++++++++\n");
      
    }
    
   
    close (socketfd);
     
  }
  
  return EXIT_SUCCESS;
}

//Print out the recieved msg
void
recvClient(uint8_t *buffer, int socketfd, struct sockaddr_in server, ssize_t bytes){
  ffloc = 0;
  //Get dhcp options from the server
  uint8_t dhcp_from_serv[MAX_DHCP_LENGTH];
  memset(dhcp_from_serv, 0, sizeof(dhcp_from_serv));
  //l is the length of the dhcp msg after msg_t
  ssize_t l = abs(sizeof(msg_t) - (MAX_DHCP_LENGTH - bytes));
  memcpy(dhcp_from_serv, buffer + sizeof(msg_t), l);
  //NAK check
  if ((dhcp_from_serv[sizeof(MAGIC_COOKIE) + 2] & 0xf) == DHCPNAK){
    msg.op = 2;
    memset(octets, 0, sizeof(octets));
    update_id_req(dhcp_from_serv + sizeof(MAGIC_COOKIE));
    fillocts(DHCPNAK);
    // options(octets, false);
    return;
  }


  printf("------------------------------------------------------\n");
  printf("BOOTP Options\n");
  printf("------------------------------------------------------\n");
  // Copy over msg_t from buffer
  memset(&msg, 0, sizeof(msg));
  memcpy(&msg, buffer, sizeof(msg));
  if (msg.hlen > 16){
    // memcpy(msg.sname, lch, strlen(lch));
    memset(&msg.chaddr, 0, strlen(lch));
    memcpy(msg.chaddr, strdup(lch), strlen(lch));
    // memset(&msg.chaddr, 0, msg.hlen);
  }
  // Print msg
  printOutput(msg, NULL);
  
  printf("------------------------------------------------------\n");
  printf("DHCP Options\n");
  printf("------------------------------------------------------\n");
  //Print out the options
  options((dhcp_from_serv + sizeof(MAGIC_COOKIE)), true);
  
  memset(octets, 0, sizeof(octets));
  //from the recv, find reqest, find servid, update
  update_id_req(dhcp_from_serv + sizeof(MAGIC_COOKIE));

  uint8_t msg_type = 0;
  //if the msgtype is offer
  if ((dhcp_from_serv[sizeof(MAGIC_COOKIE) + 2] & 0xf) == DHCPOFFER){
    msg_type = DHCPREQUEST; //make it request
  }

  //if offer, then request
  //else stop
  msg.op = 1; //set msg to request opcode
  memset(&msg.yiaddr, 0, sizeof(msg.yiaddr));
  fillocts(msg_type);


}


static bool
get_args (int argc, char **argv)
{
  int option;
  while ((option = getopt(argc, argv, "x:t:c:m:s:r:p")) != -1){
    switch (option)
    {
    case 'x': // -x N : use N as the XID field (32-bit unsigned integer) [default 42]
      /* code */
      msg.xid = htonl(strtol(optarg, NULL, 10));
      break;
    case 't': //-t N : use N as the hardware type (must be one named in src/dhcp.h) [default ETH]
      msg.htype = strtol(optarg, NULL, 10);
      update_hlen();
      break;
    case 'c':; // -c N : use N as the hardware address (chaddr) [default 0102...]
      /* code */
      if (strlen(optarg) <= 16){
        uint64_t num = strtol(optarg, NULL, 16);
        // printf("num be %ld  %0lx\n", num, num);
        uint64_t swapped = swapEndian(num, strlen(optarg)-2);
        memset(&msg.chaddr, 0, sizeof(msg.chaddr));
        memcpy(msg.chaddr, &swapped, sizeof(swapped));
        // LAST ISSUE FOR B TETS, FULL CHADDR IS NOT BEING SENT TO THE SERVER

      } else {
          memset(&msg.chaddr, 0, strlen(optarg));
          memcpy(msg.chaddr, strdup(optarg), strlen(optarg));
          lch = strdup(optarg);
      }

      break;
    case 'm':; // -m N : create DHCP message type M [default DHCPDISCOVER]
      long type = strtol(optarg, NULL, 10);
      fillocts(type);
      break;
    case 's':; // -s N.N.N.N : specify the server IP DHCP option [default 127.0.0.1]
      /* code */
      char *copy = strdup(optarg);
      char *stok = strtok(copy, ".");
      for (int i = 0; i < 4; i++){
        _servId[i] = strtol(stok, &stok, 10);
        stok = strtok(NULL, ".");
      }
      fillocts(octets[2]); // Need to reupdate octets
      break;
    case 'r':; // -r N.N.N.N : specify the requested IP DHCP option [default [127.0.0.2]
      /* code */
      char *rcopy = strdup(optarg);
      char *rtok = strtok(rcopy, ".");
      for (int i = 0; i < 4; i++){
        _req[i] = strtol(rtok, &rtok, 10);
        rtok = strtok(NULL, ".");
      }
      fillocts(octets[2]); // Need to reupdate octets
      break;

    //Ignore this at first
    case 'p': // -p : initiate the protocol (send UDP packet)
      /* code */
      p_flag = true;
      fillocts(octets[2]); // Need to reupdate octet
      break;

    default:
      return false;
    }
  }
  return true;
}

void
update_id_req(uint8_t *dhcp_msg){
  int i = 0;
  while (dhcp_msg[i] != 0xff){
    uint32_t len = dhcp_msg[i + 1];
    switch (dhcp_msg[i])
    {
    case 54: //Server Identifer
      i++; //Move to the len
      len = dhcp_msg[i]; //Get the len
      //read the addy, stored 1 spot after the len
      memset(_servId, 0, sizeof(_servId));
      memcpy(_servId, dhcp_msg + i + 1, len);
      //move pointer
      i += len;

      break;
    case 50: //Request
      i++; //Move to the len
      len = dhcp_msg[i]; //Get the len
      //read the addy, stored 1 spot after the len
      memset(_req, 0, sizeof(_req));
      memcpy(_req, dhcp_msg + i + 1, len);
      i += len;
      break;
    
    default:
      i++;
      break;
    }
  }
}

void
update_hlen(){  
  switch (msg.htype)
  {
  case ETH:
    msg.hlen = ETH_LEN;
    break;
  case IEEE802:
    msg.hlen = IEEE802_LEN;
    break;
  case ARCNET:
    msg.hlen = ARCNET_LEN;
    break;
  case FRAME_RELAY:
    msg.hlen = FRAME_LEN;
    break;
  case FIBRE:
    msg.hlen = FIBRE_LEN;
    break;
  case ATM:
    msg.hlen = ATM_LEN;
    break;
  default:
    break;
  }
}

void
fillrequest(int index, int len){
  octets[index++] = 50; //Request 
  octets[index++] = len;
  for (int i = 0; i < len; i++){
    octets[index] = _req[i];
    index++;
  }
  octets[index] = 0xff;
  ffloc = index;
}

void
fillservId(int index, int len){
  octets[index++] = 54;
  octets[index++] = len;

  for (int i = 0; i < len; i++){
    octets[index] = _servId[i];
    index++;
  }
  octets[index] = 0xff;
  ffloc = index;
}

void
fillocts(long dhcp_type){

  octets[0] = 0x35;
  octets[1] = 0x01;
  octets[3] = 0x00;
  int index = 2;
  octets[index] = dhcp_type;
  index += 1;
  switch (dhcp_type)
   {
  case DHCPOFFER:
    //Ip Lease Time
    fillservId(index, 4); //ServerIden
    break;
  case DHCPREQUEST: 
    fillrequest(index, 4); //Request 
    index += 6;
    fillservId(index, 4); //ServerIden
    break;
  case DHCPDECLINE:
    fillrequest(index, 4); //Request 
    index += 6;
    fillservId(index, 4); //ServerIden
    break;
  case DHCPACK:
    //Ip Lease Time
    fillservId(index, 4); //ServerIden
    break;
  case DHCPNAK:
    fillservId(index, 4); //ServerIden
    break;
  case DHCPRELEASE:
    fillservId(index, 4); //ServerIden
    break;
  default:
    octets[2] = DHCPDISCOVER;
    octets[3] = 0xff;
    ffloc = 3;
    break;
   }

}

uint64_t
swapEndian(long long num, int len){
    // long swapped = ((num>>5*8)&0xff)| //move 5 to 0
    //                ((num>>3*8)&0xff00)| // move 4 to 1
    //                ((num>>1*8)&0xff0000)| // move 3 to 2
    //                ((num<<1*8)&0xff000000)| // move 2 to 3
    //                ((num<<3*8)&0xff00000000)| // move 1 to 4
    //                ((num<<5*8)&0xff0000000000); // move 0 to 5

    uint64_t f = 0xff;
    int shift = (len)/2;
    long long swapped = ((num>>shift*8)&f);
    shift -= 2;
    //Shift right
    for (; shift >= 1; shift -= 2){
        f = f << 8;
        f |= 0x00; //Append 0x00 for each shift
        swapped |= (num>>shift * 8)&f;
    }
    //shift left
    for (shift = 1; shift < (len)/2 + 2; shift += 2){
      f = f << 8;
      f |= 0x00; //Append 0x00 for each shift
      swapped |= (num<<shift * 8)&f;
    }

    return swapped;  
}
