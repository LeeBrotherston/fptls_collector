/*
Exciting Licence Info.....

This file is part of FingerprinTLS.

FingerprinTLS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

FingerprinTLS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

Exciting Licence Info Addendum.....

FingerprinTLS is additionally released under the "don't judge me" program
whereby it is forbidden to rip into me too harshly for programming
mistakes, kthnxbai.

*/

// TODO
// XXX Add UDP support (not as easy as I thought, DTLS has differences... still add it though)
// XXX enhance search to include sorting per list/thread/shard/thingy
// XXX add 6in4 support (should be as simple as UDP and IPv6... in theory)
// XXX add Teredo support



#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>

/* For TimeStamping from pcap_pkthdr */
#include <time.h>

/* For the signal handler stuff */
#include <signal.h>

/* And my own signal handler functions */
#include "signal.c"

/* My own header sherbizzle */
#include "fptls_collector.h"

/* Stuff to process packets */
#include "packet_processing.c"


/*
 * print help text
 */
void print_usage(char *bin_name) {
	fprintf(stderr, "Usage: %s <options>\n\n", bin_name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -h                This message\n");
	fprintf(stderr, "    -i <interface>    Sniff packets from specified interface\n");
	fprintf(stderr, "    -p <pcap file>    Read packets from specified pcap file\n");
	fprintf(stderr, "    -P <pcap file>    Save packets to specified pcap file for unknown fingerprints\n");
	fprintf(stderr, "    -l <log file>     Output logfile (JSON format)\n");
	fprintf(stderr, "    -d                Show reasons for discarded packets (post BPF)\n");
	fprintf(stderr, "    -u <uid>          Drop privileges to specified UID (not username)\n");
	fprintf(stderr, "\n");
	return;
}

/* Testing another way of searching the in memory database */
uint shard_fp (struct fingerprint_new *fp_lookup, uint16_t maxshard) {
				return (((fp_lookup->ciphersuite_length) + (fp_lookup->tls_version)) & (maxshard -1));
}

int main(int argc, char **argv) {

	char *dev = NULL;											/* capture device name */
	char *unpriv_user = NULL;							/* User for dropping privs */
	char errbuf[PCAP_ERRBUF_SIZE];				/* error buffer */
	extern pcap_t *handle;								/* packet capture handle */
	extern pcap_dumper_t *output_handle;					/* output to pcap handle */

	char *filter_exp = default_filter;
	int arg_start = 1, i;
	extern struct bpf_program fp;					/* compiled filter program (expression) */

	extern FILE *json_fd, *log_fd;
	extern int show_drops;
	extern char hostname[HOST_NAME_MAX];
	show_drops = 0;


	/* Make sure pipe sees new packets unbuffered. */
	//setvbuf(stdout, (char *)NULL, _IOLBF, 0);
	setlinebuf(stdout);

	if (argc == 1) {
		print_usage(argv[0]);
		exit(-1);
	}
	/* Do the -something switches  - yes this isn't very nice and doesn't support -abcd */
	for (i = arg_start; i < argc && argv[i][0] == '-' ; i++) {
		switch (argv[i][1]) {
			case '?':
			case 'h':
				print_usage(argv[0]);
				exit(0);
				break;
			case 'p':
				/* Open the file */
				/* Check if interface already set */
				if (handle != NULL) {
					printf("-p and -i are mutually exclusive\n");
					exit(-1);
				}
				handle = pcap_open_offline(argv[++i], errbuf);
				printf("Reading from file: %s\n", argv[i]);
				break;
			case 'P':
				/* Open the file */
				output_handle = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535), argv[++i]);
				if (output_handle != NULL) {
					printf("Writing samples to file: %s\n", argv[i]);
				} else {
					printf("Could not save samples: %s\n", errbuf);
					exit(-1);
				}
				break;
			case 'i':
				/* Open the interface */
				/* Check if file already successfully opened, if bad filename we can fail to sniffing */
				if (handle != NULL) {
					printf("-p and -i are mutually exclusive\n");
					exit(-1);
				}
				handle = pcap_open_live(argv[++i], SNAP_LEN, 1, 1000, errbuf);
				printf("Using interface: %s\n", argv[i]);
				break;
			case 'l':
				/* Output to log file */
				if((log_fd = fopen(argv[++i], "a")) == NULL) {
					printf("Cannot open log file for output\n");
					exit(-1);
				}
				json_fd = log_fd;
				// Buffering is fine, but linebuf needed for tailers to work properly
				setlinebuf(log_fd);
				break;
			case 's':
				/* JSON output to stdout */
				if((json_fd = fopen("/dev/stdout", "a")) == NULL) {
					printf("Cannot open JSON file for output\n");
					fprintf(json_fd, "FD TEST\n");
					exit(-1);
				}
				break;
			case 'd':
				/* Show Dropped Packet Info */
				show_drops = 1;
				break;
			case 'u':
				/* User for dropping privileges to */
				unpriv_user = argv[++i];
				break;
			default :
				printf("Unknown option '%s'\n", argv[i]);
				exit(-1);
				break;

		}
	}

	/* Checks required directly after switches are set */


	/* Interface should already be opened, and files read we can drop privs now */
	/* This should stay the first action as lowering privs reduces risk from any subsequent actions */
	/* being poorly implimented and running as root */
	if (unpriv_user != NULL) {
		if (setgid(getgid()) == -1) {
  		fprintf(stderr, "WARNING: could not drop group privileges\n");
		} else {
			fprintf(stderr, "Dropped effective group successfully\n");
		}
		if (setuid(atoi(unpriv_user)) == -1) {
			fprintf(stderr, "WARNING: could not drop privileges to specified UID\n");
		} else {
			fprintf(stderr, "Changed UID successfully\n");
		}
	}

	// Register signal Handlers
	if(!(register_signals())) {
		printf("Could not register signal handlers\n");
		exit(0);
	}


	/* XXX HORRIBLE HORRIBLE KLUDGE TO AVOID if's everywhere.  I KNOW OK?! */
	if(json_fd == NULL) {
		if((json_fd = fopen("/dev/null", "a")) == NULL) {
			printf("Cannot open JSON file (/dev/null) for output\n");
			exit(-1);
		}
	}

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open source %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	/* netmask is set to 0 because we don't care and it saves looking it up :) */
	if (pcap_compile(handle, &fp, default_filter, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* setup hostname variable for use in logs (incase of multiple hosts) */
	if(gethostname(hostname, HOST_NAME_MAX) != 0) {
		sprintf(hostname, "unknown");
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	fprintf(stderr, "Reached end of pcap\n");

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}
