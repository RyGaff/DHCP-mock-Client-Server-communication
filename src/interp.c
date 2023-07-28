#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "dhcp.h"
#include "format.h"
/* This work complies with the JMU Honor Code.
 * References and Acknowledgments: I received no outside
 * help with this programming assignment. */

int
main (int argc, char **argv)
{
  // Open the file from the command line
  FILE *fp;
  if (argc < 1){
    return EXIT_SUCCESS;
  }

  fp = fopen(argv[1],"r");
  if (!fp){
    puts("No file found");
    return EXIT_FAILURE;
  }

  // Read into the msg_t
  printf("------------------------------------------------------\n");
  printf("BOOTP Options\n");
  printf("------------------------------------------------------\n");
  msg_t msg = populateMessage(fp);

  printOutput(msg, ":/");

  //if file is bigger than msg do dhcp
  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (size > sizeof(msg)){
    printf("------------------------------------------------------\n");
    printf("DHCP Options\n");
    printf("------------------------------------------------------\n");
    // Check for cookie
    if (checkCookie(fp)){ 
      //One octet is 8 bits which is 1 byte
      uint8_t octets[MAX_DHCP_LENGTH];
      memset(octets, 0, sizeof(octets));
      fread(octets, sizeof(uint8_t), MAX_DHCP_LENGTH, fp);
      dump_packet (octets, sizeof(octets));
      options(octets, false);
    }
  }


  fclose(fp);
  return EXIT_SUCCESS;
}
