#include <stdio.h>

#include "dhcp.h"
#include "format.h"
/* This work complies with the JMU Honor Code.
 * References and Acknowledgments: I received no outside
 * help with this programming assignment. */

void
dump_msg (FILE *output, msg_t *msg, size_t size)
{
  fprintf (output, "------------------------------------------------------\n");
  fprintf (output, "BOOTP Options\n");
  fprintf (output, "------------------------------------------------------\n");

  fprintf (output, "------------------------------------------------------\n");
  fprintf (output, "DHCP Options\n");
  fprintf (output, "------------------------------------------------------\n");
}
