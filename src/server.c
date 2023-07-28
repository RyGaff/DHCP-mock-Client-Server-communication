#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "dhcp.h"
#include "format.h"
#include "port_utils.h"
/* This work complies with the JMU Honor Code.
 * References and Acknowledgments: I received no outside
 * help with this programming assignment. */

static bool get_args (int, char **);

static bool debug = false;

int
main (int argc, char **argv)
{
  if (debug)
    fprintf (stderr, "Shutting down\n");

  return EXIT_SUCCESS;
}

static bool
get_args (int argc, char **argv)
{
  int ch = 0;
  while ((ch = getopt (argc, argv, "dh")) != -1)
    {
      switch (ch)
        {
        case 'd':
          debug = true;
          break;
        default:
          return false;
        }
    }
  return true;
}
