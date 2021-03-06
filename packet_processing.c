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


// XXX as expected there is a memory leak, because I've been a bit yeeehaw with malloc in doing this test
// check through the code to make sure mallocs and frees are all matched up. (may be fixed?)

// XXX reuse alloc'd space

// Just leave this here...

//  CREATE TABLE IF NOT EXISTS queue (event TEXT NOT NULL, ip_version TEXT NOT NULL, ipv4_dst TEXT, ipv4_src TEXT, ipv6_dst TEXT, ipv6_src TEXT, src_port NUM, dst_port NUM, timestamp TEXT, tls_version TEXT, server_name TEXT, record_tls_version TEXT, sig_alg BLOB, extensions BLOB, ec_point_fmt BLOB, e_curves BLOB, connection TEXT, compression_length TEXT, ciphersuite_length INT, ciphersuite BLOB, compression BLOB);

uint shardnum (uint16_t port1, uint16_t port2, uint16_t maxshard) {
				return (((port1 >> 8) + (port2 >> 8)) & (maxshard - 1));
}



void got_packet(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *packet) {
		/* ************************************************************************* */
		/* Variables, gotta have variables, and structs and pointers....  and things */
		/* ************************************************************************* */

		extern FILE *log_fd, *log_fd;
		extern int newsig_count;
		extern char hostname[HOST_NAME_MAX];

		int size_ip = 0;
		int size_tcp;
		uint size_payload;  //  Check all these for appropiate variable size.  Was getting signed negative value and failing tests XXX
		int size_vlan_offset=0;
		int arse;  // Random counter - relocated to allow use elsewhere during testing


		int ip_version=0;
		int af_type;
		char src_address_buffer[64];
		char dst_address_buffer[64];

		struct timeval packet_time;
		struct tm print_time;
		char printable_time[64];

		static struct fingerprint_new *fp_packet = NULL;			/* Generated fingerprint for incoming packet */
		static uint16_t	extensions_malloc = 0;							/* how much is currently allocated for the extensions field */

		extern pcap_dumper_t *output_handle;					/* output to pcap handle */

		/* pointers to key places in the packet headers */
		struct ether_header *ethernet;	/* The ethernet header [1] */
		struct ipv4_header *ipv4;         /* The IPv4 header */
		struct ip6_hdr *ipv6;             /* The IPv6 header */
		struct tcp_header *tcp;           /* The TCP header */
		struct udp_header *udp;           /* The UDP header */
		struct teredo_header *teredo;			/* Teredo header */


		u_char *payload;                  /* Packet payload */

		char *server_name;						/* Server name per the extension */


		/* Prepared statement for sqlite insertion */
		//                  "INSERT into queue (   1     ,  2  ,     3    ,   4    ,    5   ,    6   ,   7    ,    8   ,   9    ,    10     ,     11    ,        12        ,        13        ,     14    ,        15        ,    16     ,   17     ,   18  ,     19     ,   20   ,     21   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
		char insert_sql[] = "INSERT into queue (timestamp,event,ip_version,ipv4_src,ipv4_dst,src_port,dst_port,ipv6_src,ipv6_dst,tls_version,server_name,record_tls_version,ciphersuite_length,ciphersuite,compression_length,compression,extensions,sig_alg,ec_point_fmt,e_curves,connection) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
		int return_code;
		sqlite3_stmt *insert_statement = NULL;

		/*
			Check if this is uninitialised at this point and initialise if so.  This saves us copying
			in the event that we need a new fingerprint, we already have a populated fingerprint structs
			for the most part (barring a couple of memcpy's).  This should reduce the time to insert
			new signatures.
		*/
		if(fp_packet == NULL) {
			fp_packet = malloc(sizeof(struct fingerprint_new));
			if(fp_packet == NULL) {
				printf("Malloc Error (fp_packet)\n");
				exit(0);
			}
		}


		/* ************************************* */
		/* Anything we need from the pcap_pkthdr */
		/* ************************************* */

		/*
			In theory time doesn't need to be first because it's saved in the PCAP
			header, however I am keeping it here incase we derive it from somewhere
			else in future and we want it early in the process.
		*/

		packet_time = pcap_header->ts;
		print_time = *localtime(&packet_time.tv_sec);
		strftime(printable_time, sizeof printable_time, "%FT%T%z", &print_time);


		/* ******************************************** */
		/* Set pointers to the main parts of the packet */
		/* ******************************************** */

		/*
			Ethernet
		*/

		/*
			Section to deal with random low layer stuff before we get to IP
		*/

		ethernet = (struct ether_header*)(packet);
		switch(ntohs(ethernet->ether_type)) {
			/*
				De-802.1Q things if needed.  This isn't in the switch below so that we don't have to loop
				back around for IPv4 vs v6 ethertype handling.  This is a special case that we just detangle
				upfront.  Also avoids a while loop, woo!
			*/
			case ETHERTYPE_VLAN:
				// Using loop to account for double tagging (can you triple?!)
				for(size_vlan_offset=4;  ethernet->ether_type == ETHERTYPE_VLAN ; size_vlan_offset+=4) {
					ethernet = (struct ether_header*)(packet+size_vlan_offset);
				}
				break;
			/* PPPoE */
			case 0x8864:
				// XXX Need to research further but seems skipping 8 bytes is all we need?  But how.... hmmmm...
				//ethernet = (struct ether_header*)(packet + size_vlan_offset + 8);

				//  This is just a placeholder for now.  BPF will probably need updating.
				printf("PPPoE\n");
				break;
		}

		// Now we can deal with what the ether_type is
		switch(ntohs(ethernet->ether_type)){
			case ETHERTYPE_IP:
				/* IPv4 */
				ip_version=4;
				af_type=AF_INET;
				break;
			//case ETHERTYPE_IPV6:
			case 0x86dd:
				/* IPv6 */
				ip_version=6;
				af_type=AF_INET6;
				break;
			default:
				/* Something's gone wrong... Doesn't appear to be a valid ethernet frame? */
				if (show_drops)
					fprintf(stderr, "[%s] Malformed Ethernet frame\n", printable_time);
				return;
		}


		/*
			Sadly BPF filters are not equal between IPv4 and IPv6 so we cannot rely on them for everything, so
			this section attempts to cope with that.
		*/

		/*
			IP headers
		*/
		switch(ip_version) {
			case 4:
				/* IP Header */
				ipv4 = (struct ipv4_header*)(packet + SIZE_ETHERNET + size_vlan_offset);
				size_ip = IP_HL(ipv4)*4;

				if (size_ip < 20) {
					/* This is just wrong, not even bothering */
					if(show_drops)
						fprintf(stderr, "[%s] Packet Drop: Invalid IP header length: %u bytes\n", printable_time, size_ip);
					return;
				}
				if(show_drops) {
					fprintf(stderr, "[%s] Packet Passed header length: %u bytes\n", printable_time, size_ip);
				}

				/* Protocol */
				switch(ipv4->ip_p) {
					case IPPROTO_TCP:
						break;

					case IPPROTO_UDP:
						/*
							As it stands currently, the BPF should ensure that the *only* UDP is Teredo with TLS IPv6 packets inside,
							thus I'm going to assume that is the case for now and set ip_version to 5 (4 to 6 intermediary as I will
							never have to support actual IPv5).
						*/
						ip_version = 7;

						udp = (struct udp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip);
						teredo = (struct teredo_header*)(udp + 1);  /* +1 is UDP header, not bytes ;) */
						//tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip + 8 + sizeof(struct teredo_header));

						/* setting offset later with size_ip manipulation...  may need to ammend this */
						size_ip += sizeof(struct udp_header) + sizeof(struct teredo_header);
						break;

					case 0x29:
						/* Not using this yet, but here ready for when I impliment 6in4 de-encapsultion (per teredo) */
						ip_version = 8;  // No reason... YOLO
						ipv6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET + size_vlan_offset + sizeof(struct ipv4_header));
						size_ip += 40;
						break;

					default:
						/* Not TCP, not trying.... don't care.  The BPF filter should
						 * prevent this happening, but if I remove it you can guarantee I'll have
						 * forgotten an edge case :) */
						 if (show_drops)
						 	fprintf(stderr, "[%s] Packet Drop: non-TCP made it though the filter... weird\n", printable_time);
						return;
				}
				break;

			case 6:
				/* IP Header */
				ipv6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET + size_vlan_offset);
				size_ip = 40;

				// XXX These lines are duplicated, will de-dupe later this is for testing without breaking :)
				tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip);
				payload = (u_char *)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip + (tcp->th_off * 4));

				/* Sanity Check... Should be IPv6 */
				if ((ntohl(ipv6->ip6_vfc)>>28)!=6){
					if(show_drops)
						fprintf(stderr, "[%s] Packet Drop: Invalid IPv6 header\n", printable_time);
					return;
				}

				switch(ipv6->ip6_nxt){
					case 6:		/* TCP */
						break;
					case 17:	/* UDP */
					case 58:	/* ICMPv6 */
						if(show_drops)
						 	fprintf(stderr, "[%s] Packet Drop: non-TCP made it though the filter... weird\n", printable_time);
						return;

					default:
						printf("[%s] Packet Drop: Unhandled IPv6 next header: %i\n",printable_time, ipv6->ip6_nxt);
						return;
				}

		}

		/*
			TCP/UDP/Cabbage/Jam
		*/
		/* Yay, it's TCP, let's set the pointer */
		tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip);

		size_tcp = (tcp->th_off * 4);
		if (size_tcp < 20) {
			/* Not even trying if this is the case.... kthnxbai */
			if(show_drops)
				printf("[%s] Packet Drop: Invalid TCP header length: %u bytes\n", printable_time, size_tcp);
			return;
		}

		/*
			Packet Payload
		*/

		/* Set the payload pointer */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip + (tcp->th_off * 4));

		/* ------------------------------------ */

		/* How big is our payload, according to header info ??? */
		size_payload = (pcap_header->len - SIZE_ETHERNET - size_vlan_offset - size_ip - (tcp->th_off * 4));
		/* ---------------------------------------------------- */


		/* ******************************************************** */
		/* Some basic checks, ignore the packet if it vaguely fails */
		/* ******************************************************** */

		/* Check it's actually a valid TLS version - this seems to prevent most false positives */
		switch ((payload[OFFSET_HELLO_VERSION]*256) + payload[OFFSET_HELLO_VERSION+1]) {
			/* Valid TLS Versions */
			/* Yeah - SSLv2 isn't formatted this way, what a PITA! */
			//case 0x002:	/* SSLv2 */
			case 0x300:	/* SSLv3 */
			case 0x301:	/* TLSv1 */
			case 0x302:	/* TLSv1.1 */
			case 0x303:	/* TLSv1.2 */
				break;
			default:
				/* Doesn't look like a valid TLS version.... probably not even a TLS packet, if it is, it's a bad one */
				if(show_drops)
					printf("[%s] Packet Drop: Bad TLS Version %X%X\n", printable_time, payload[OFFSET_HELLO_VERSION], payload[OFFSET_HELLO_VERSION+1]);
				return;
		}

		/* Check the size of the sessionid */
		const u_char *packet_data = &payload[OFFSET_SESSION_LENGTH];
		if (size_payload < OFFSET_SESSION_LENGTH + packet_data[0] + 3) {
			if(show_drops)
				printf("[%s] Packet Drop: Session ID looks bad [%i] [%i]\n", printable_time, size_payload, (OFFSET_SESSION_LENGTH + packet_data[0] + 3) );
			return;
		}

		/* ************************************************************************ */
		/* The bit that grabs the useful info from packets (or sets pointers to it) */
		/* ************************************************************************ */


		/* TLS Version (Record Layer - not proper proper) */
		fp_packet->record_tls_version = (payload[1]*256) + payload[2];

		/* TLS Version */
		fp_packet->tls_version = (payload[OFFSET_HELLO_VERSION]*256) + payload[OFFSET_HELLO_VERSION+1];

		/* CipherSuite */
		packet_data += 1 + packet_data[0];
		u_short cs_len = packet_data[0]*256 + packet_data[1];

		/* Check that the offset doesn't push the pointer off the end of the payload */
		if((packet_data + cs_len) >= (payload + size_payload)) {
			if(show_drops == 1) {
				fprintf(stderr, "CipherSuite length offset beyond end of packet");
			}
			return;
		}

		/* Length */
		fp_packet->ciphersuite_length = (packet_data[0]*256) + packet_data[1];


		/*
			CipherSuites
		*/
		packet_data += 2; // skip cipher suites length
		fp_packet->ciphersuite = (uint8_t *)packet_data;

		/*
			Compression
		*/
		u_short comp_len = packet_data[cs_len];

		/* Check that the offset doesn't just past the end of the packet */
		if((packet_data + comp_len) >= (payload + size_payload)) {
			if(show_drops == 1) {
				fprintf(stderr, "Compression length offset beyond end of packet");
			}
			return;
		}
		/*
			Length
		*/
		fp_packet->compression_length = comp_len;

		/*
			Compression List
		*/
		packet_data += cs_len + 1;
		fp_packet->compression = (uint8_t *)packet_data;

		/*
			Extensions
		*/
		u_short ext_len = packet_data[comp_len]*256 + packet_data[comp_len+1];
		int ext_id, ext_count = 0;

		/* Check extension length doesn't run over the end of the packet */
		if((packet_data + ext_len) >= (payload + size_payload)) {
			if(show_drops == 1) {
				fprintf(stderr, "Extension length offset Beyond end of packet");
			}
			return;
		}

		/*
			Length
		*/
		packet_data += comp_len + 2;

		/*
			Set optional data to NULL in advance
		*/
		fp_packet->curves = NULL;
		fp_packet->sig_alg = NULL;
		fp_packet->ec_point_fmt = NULL;
		server_name = NULL;


		/*
			So this works - so overall length seems ok
		*/
		uint8_t *extensions_tmp_ptr = (uint8_t *)packet_data;

		/*
			If we are at the end of the packet we have no extensions, without this
			we will just run off the end of the packet into unallocated space :/
		*/
		if(packet_data - payload > size_payload) {
			ext_len = 0;
		}
		/* Loop through the extensions */
		fp_packet->extensions_length = 0;
		for (ext_id = 0; ext_id < ext_len ; ext_id++ ) {
			int ext_type;

			/* Set the extension type */
			ext_type = (packet_data[ext_id]*256) + packet_data[ext_id + 1];
			ext_count++;

			/* Handle some special cases */
			switch(ext_type) {
				case 0x000a:
					/* elliptic_curves */
					fp_packet->curves = (uint8_t *)&packet_data[ext_id + 2];
					/* 2 & 3, not 0 & 1 because of 2nd length field */
					fp_packet->curves_length = fp_packet->curves[2]*256 + fp_packet->curves[3];
					break;
				case 0x000b:
					/* ec_point formats */
					fp_packet->ec_point_fmt = (uint8_t *)&packet_data[ext_id + 2];
					fp_packet->ec_point_fmt_length = fp_packet->ec_point_fmt[2];
					//printf("ec point length: %i\n", fp_packet->ec_point_fmt_length);
					break;
				case 0x000d:
					/* Signature algorithms */
					fp_packet->sig_alg = (uint8_t *)&packet_data[ext_id + 2];
					fp_packet->sig_alg_length = fp_packet->sig_alg[2]*256 + fp_packet->sig_alg[3];
					break;
				case 0x0000:
					/* Definitely *NOT* signature-worthy
					 * but worth noting for debugging source
					 * of packets during signature creation.
					 */
					/* Server Name */
					server_name = (char *)&packet_data[ext_id+2];
					break;

				/* Some potential new extenstions to exploit for fingerprint material */
				/* Need to be tested for consistent values before deploying though    */
				case 0x0015:
					/* Padding */
					/* XXX Need to check if padding length is consistent or varies (varies is not useful to us) */
					break;
				case 0x0010:
					/* application_layer_protocol_negotiation */

					break;
				case 0x000F:
					/* HeartBeat (as per padding, is this consistent?) */

					break;
			}
			fp_packet->extensions_length = (ext_count * 2);

			/* Increment past the payload of the extensions */
			ext_id += (packet_data[ext_id + 2]*256) + packet_data[ext_id + 3] + 3;

			if((packet_data + ext_id) >= (payload + size_payload)) {
				if(show_drops == 1) {
					fprintf(stderr, "Extension offset beyond end of packet");
				}
				return;
			}

		}

		/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
		// XXX Check that curves are working (being matched, etc)
		uint8_t *realcurves = fp_packet->curves;
		if (fp_packet->curves != NULL) {
			realcurves += 4;
		} else {
			realcurves = NULL;
			fp_packet->curves_length = 0;
		}
		/* ******************************************************************** */

		/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
		uint8_t *realsig_alg = fp_packet->sig_alg;
			if(fp_packet->sig_alg != NULL) {
			realsig_alg += 4;
			fp_packet->sig_alg = realsig_alg;
		} else {
			realsig_alg = NULL;
			fp_packet->sig_alg_length = 0;
		}
		/* ******************************************************************** */

		/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
		uint8_t *realec_point_fmt = fp_packet->ec_point_fmt;
		if(fp_packet->ec_point_fmt != NULL) {
			realec_point_fmt += 3;
		} else {
			realec_point_fmt = NULL;
			fp_packet->ec_point_fmt_length = 0;
		}
		/* ******************************************************************** */



		/*
			Extensions use offsets, etc so we can alloc those now.  Others however will just have pointers
			and we can malloc if it becomes a signature.  For this reason we have extensions_malloc to track
			the current size for easy reuse instead of consantly malloc and free'ing the space.
		*/

		if(extensions_malloc == 0) {
			fp_packet->extensions = malloc(fp_packet->extensions_length);
			extensions_malloc = fp_packet->extensions_length;
		} else{
			if(fp_packet->extensions_length > extensions_malloc) {
				fp_packet->extensions = realloc(fp_packet->extensions, fp_packet->extensions_length);
				extensions_malloc = fp_packet->extensions_length;
			}
		}
		if(fp_packet->extensions == NULL) {
			printf("Malloc Error (extensions)\n");
			exit(0);
		}

		// Load up the extensions
		int unarse = 0;
		for (arse = 0 ; arse < ext_len ;) {
			fp_packet->extensions[unarse] = (uint8_t) extensions_tmp_ptr[arse];
			fp_packet->extensions[unarse+1] = (uint8_t) extensions_tmp_ptr[arse+1];
			unarse += 2;
			arse = arse + 4 + (((uint8_t) extensions_tmp_ptr[(arse+2)])*256) + (uint8_t)(extensions_tmp_ptr[arse+3]);
		}


		/*
		 * Going to get ready for some sqlite insert action here too
		 */

		 /* Compile the prepared statement, we will then bind variables */
		 return_code = sqlite3_prepare_v2(sqlite_db, insert_sql, strlen(insert_sql), &insert_statement, NULL);



		/*
		 * New output format.  JSON to allow easier automated parsing.
		 */
		 fprintf(log_fd,  "{ "); // May need more header to define type?
		 fprintf(log_fd,  "\"timestamp\": \"%s\", ", printable_time);
		 fprintf(log_fd,  "\"event\": \"connection\", ");

		 /* XXX check return code on each bind */
		 return_code = sqlite3_bind_text(insert_statement, 1, printable_time, sizeof(printable_time), NULL);
		 return_code = sqlite3_bind_text(insert_statement, 2, "connection", sizeof("connection"), NULL);

		 fprintf(log_fd,  "\"ip_version\": ");
		 switch(ip_version) {
			 case 4:
			 	/* IPv4 */
				fprintf(log_fd,  "\"ipv4\", ");
				inet_ntop(AF_INET,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(AF_INET,(void*)&ipv4->ip_dst,dst_address_buffer,sizeof(dst_address_buffer));
				fprintf(log_fd,  "\"ipv4_src\": \"%s\", ", src_address_buffer);
				fprintf(log_fd,  "\"ipv4_dst\": \"%s\", ", dst_address_buffer);

				fprintf(log_fd,  "\"src_port\": %hu, ", ntohs(tcp->th_sport));
				fprintf(log_fd,  "\"dst_port\": %hu, ", ntohs(tcp->th_dport));

				return_code = sqlite3_bind_text(insert_statement, 3, "ipv4", sizeof("ipv4"), NULL);
				return_code = sqlite3_bind_text(insert_statement, 4, src_address_buffer, sizeof(src_address_buffer), NULL);
				return_code = sqlite3_bind_text(insert_statement, 5, dst_address_buffer, sizeof(dst_address_buffer), NULL);
				return_code = sqlite3_bind_int(insert_statement, 6, ntohs(tcp->th_sport));
				return_code = sqlite3_bind_int(insert_statement, 7, ntohs(tcp->th_dport));

				break;
			 case 6:
			 	/* IPv6 */
				fprintf(log_fd,  "\"ipv6\", ");
				inet_ntop(AF_INET6,(void*)&ipv6->ip6_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(AF_INET6,(void*)&ipv6->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
				fprintf(log_fd,  "\"ipv6_src\": \"%s\", ", src_address_buffer);
				fprintf(log_fd,  "\"ipv6_dst\": \"%s\", ", dst_address_buffer);

				fprintf(log_fd,  "\"src_port\": %hu, ", ntohs(tcp->th_sport));
				fprintf(log_fd,  "\"dst_port\": %hu, ", ntohs(tcp->th_dport));

				return_code = sqlite3_bind_text(insert_statement, 3, "ipv6", sizeof("ipv6"), NULL);
				return_code = sqlite3_bind_text(insert_statement, 8, src_address_buffer, sizeof(src_address_buffer), NULL);
				return_code = sqlite3_bind_text(insert_statement, 9, dst_address_buffer, sizeof(dst_address_buffer), NULL);
				return_code = sqlite3_bind_int(insert_statement, 6, ntohs(tcp->th_sport));
				return_code = sqlite3_bind_int(insert_statement, 7, ntohs(tcp->th_dport));

				break;
			 case 7:
			 	/*
				 * Teredo.  As this is an IPv6 within IPv4 tunnel, both sets of address are logged.
				 * The field names remain the same for ease of reporting on "all traffic from X" type
				 * scenarios, however the "ip_version" field makes it clear that this is an encapsulted
				 * tunnel.
				 */
				fprintf(log_fd,  "\"teredo\", ");

				return_code = sqlite3_bind_text(insert_statement, 3, "teredo", sizeof("teredo"), NULL);

				inet_ntop(AF_INET,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(AF_INET,(void*)&ipv4->ip_dst,dst_address_buffer,sizeof(dst_address_buffer));
				fprintf(log_fd,  "\"ipv4_src\": \"%s\", ", src_address_buffer);
				fprintf(log_fd,  "\"ipv4_dst\": \"%s\", ", dst_address_buffer);

				return_code = sqlite3_bind_text(insert_statement, 4, src_address_buffer, sizeof(src_address_buffer), NULL);
				return_code = sqlite3_bind_text(insert_statement, 5, dst_address_buffer, sizeof(dst_address_buffer), NULL);


				inet_ntop(AF_INET6,(void*)&ipv6->ip6_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(AF_INET6,(void*)&ipv6->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
				fprintf(log_fd,  "\"ipv6_src\": \"%s\", ", src_address_buffer);
				fprintf(log_fd,  "\"ipv6_dst\": \"%s\", ", dst_address_buffer);

				return_code = sqlite3_bind_text(insert_statement, 8, src_address_buffer, sizeof(src_address_buffer), NULL);
				return_code = sqlite3_bind_text(insert_statement, 9, dst_address_buffer, sizeof(dst_address_buffer), NULL);


				fprintf(log_fd,  "\"src_port\": %hu, ", ntohs(tcp->th_sport));
				fprintf(log_fd,  "\"dst_port\": %hu, ", ntohs(tcp->th_dport));

				return_code = sqlite3_bind_int(insert_statement, 6, ntohs(tcp->th_sport));
				return_code = sqlite3_bind_int(insert_statement, 7, ntohs(tcp->th_dport));

				/* Add in ports of the outer Teredo tunnel? */



				break;
			 case 8:
			 	/*
				 * 6in4. 	As this is an IPv6 within IPv4 tunnel, both sets of address are logged.
				 * The field names remain the same for ease of reporting on "all traffic from X" type
				 * scenarios, however the "ip_version" field makes it clear that this is an encapsulted
				 * tunnel.
				 */
				fprintf(log_fd,  "\"6in4\", ");

				return_code = sqlite3_bind_text(insert_statement, 3, "6in4", sizeof("6in4"), NULL);


				inet_ntop(AF_INET,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(AF_INET,(void*)&ipv4->ip_dst,dst_address_buffer,sizeof(dst_address_buffer));
				fprintf(log_fd,  "\"ipv4_src\": \"%s\", ", src_address_buffer);
				fprintf(log_fd,  "\"ipv4_dst\": \"%s\", ", dst_address_buffer);

				return_code = sqlite3_bind_text(insert_statement, 4, src_address_buffer, sizeof(src_address_buffer), NULL);
				return_code = sqlite3_bind_text(insert_statement, 5, dst_address_buffer, sizeof(dst_address_buffer), NULL);


				inet_ntop(AF_INET6,(void*)&ipv6->ip6_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(AF_INET6,(void*)&ipv6->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
				fprintf(log_fd,  "\"ipv6_src\": \"%s\", ", src_address_buffer);
				fprintf(log_fd,  "\"ipv6_dst\": \"%s\", ", dst_address_buffer);

				return_code = sqlite3_bind_text(insert_statement, 8, src_address_buffer, sizeof(src_address_buffer), NULL);
				return_code = sqlite3_bind_text(insert_statement, 9, dst_address_buffer, sizeof(dst_address_buffer), NULL);


				fprintf(log_fd,  "\"src_port\": %hu, ", ntohs(tcp->th_sport));
				fprintf(log_fd,  "\"dst_port\": %hu, ", ntohs(tcp->th_dport));

				return_code = sqlite3_bind_int(insert_statement, 6, ntohs(tcp->th_sport));
				return_code = sqlite3_bind_int(insert_statement, 7, ntohs(tcp->th_dport));

				break;
		 }

		 fprintf(log_fd,  "\"tls_version\": \"%s\", ", ssl_version(fp_packet->tls_version));
		 return_code = sqlite3_bind_text(insert_statement, 10, ssl_version(fp_packet->tls_version), sizeof(ssl_version(fp_packet->tls_version)), NULL);


		 fprintf(log_fd,  "\"server_name\": \"");

		if(server_name != NULL) {
				for (arse = 7 ; arse <= (server_name[0]*256 + server_name[1]) + 1 ; arse++) {
					if (server_name[arse] > 0x20 && server_name[arse] < 0x7b)
						fprintf(log_fd,  "%c", server_name[arse]);
				}
				return_code = sqlite3_bind_text(insert_statement, 11, server_name + 7, ((server_name[0]*256 + server_name[1]) - 5), NULL);
		}

		fprintf(log_fd,  "\", \"fingerprint\": ");


		/* ********************************************* */

		// Should just for log_fd being /dev/null and skip .. optimisation...
		// or make an output function linked list XXX
		fprintf(log_fd,  "{ ");

		fprintf(log_fd,  "\"record_tls_version\": \"%.04X\", ", fp_packet->record_tls_version);
		return_code = sqlite3_bind_text(insert_statement, 12, ssl_version(fp_packet->record_tls_version), sizeof(ssl_version(fp_packet->record_tls_version)), NULL);


		fprintf(log_fd,  "\"tls_version\": \"%.04X\", \"ciphersuite_length\": \"%.04X\", ",
			fp_packet->tls_version, fp_packet->ciphersuite_length);
		/* TLS Version was actually done earlier */

		/* XXX This is a (decimal) int, may remove as length(ciphersuite) will obtain this without the need for storage */
		return_code = sqlite3_bind_int(insert_statement, 13, fp_packet->ciphersuite_length);


		fprintf(log_fd,  "\"ciphersuite\": \"");
		for (arse = 0; arse < fp_packet->ciphersuite_length; ) {
			fprintf(log_fd,  "%.02X", (uint8_t) fp_packet->ciphersuite[arse]);
			arse++;
		}

		fprintf(log_fd,  "\", ");

		/* using blob to save conversion, etc.  Can use the hex() function in SQLite to get a hex representation */
		return_code = sqlite3_bind_blob(insert_statement, 14, fp_packet->ciphersuite, fp_packet->ciphersuite_length, NULL);
		if (return_code != SQLITE_OK) {
			fprintf(stderr, "sqlite3 error: %i\n", return_code);
		}



		fprintf(log_fd,  "\"compression_length\": \"%i\", ",
			fp_packet->compression_length);

		/* XXX This is a (decimal) int, may remove as length(compression) will obtain this without the need for storage */
		return_code = sqlite3_bind_int(insert_statement, 15, fp_packet->compression_length);



		fprintf(log_fd,  " \"compression\": \"");
		for (arse = 0; arse < fp_packet->compression_length; ) {
			fprintf(log_fd,  "%.02X", (uint8_t) fp_packet->compression[arse]);
			arse++;
		}
		fprintf(log_fd,  "\", ");

		/* using blob to save conversion, etc.  Can use the hex() function in SQLite to get a hex representation */
		return_code = sqlite3_bind_blob(insert_statement, 16, fp_packet->compression, fp_packet->compression_length, NULL);


		fprintf(log_fd,  "\"extensions\": \"");
		for (arse = 0 ; arse < fp_packet->extensions_length ;) {
			fprintf(log_fd,  "%.02X", (uint8_t) fp_packet->extensions[arse]);
			arse++;
		}
		fprintf(log_fd,  "\"");

		/* using blob to save conversion, etc.  Can use the hex() function in SQLite to get a hex representation */
		return_code = sqlite3_bind_blob(insert_statement, 17, fp_packet->extensions, fp_packet->extensions_length, NULL);


		if(realcurves != NULL) {
			fprintf(log_fd, ", \"e_curves\": \"");

			for (arse = 0 ; arse < fp_packet->curves_length &&
				fp_packet->curves_length > 0 ; arse++) {

				fprintf(log_fd, "%.02X", (uint8_t)realcurves[arse]);

			}
			fprintf(log_fd, "\"");
			return_code = sqlite3_bind_blob(insert_statement, 20, realcurves, fp_packet->curves_length, NULL);
		}



		if(realsig_alg != NULL) {
			fprintf(log_fd,  ", \"sig_alg\": \"");

			for (arse = 0 ; arse < (fp_packet->sig_alg_length) &&
				fp_packet->sig_alg_length > 0 ; arse++) {

				fprintf(log_fd,  "%.2X", (uint8_t) realsig_alg[arse]);
			}
			fprintf(log_fd,  "\"");
			return_code = sqlite3_bind_blob(insert_statement, 18, realsig_alg, fp_packet->sig_alg_length, NULL);
		}

		if(realec_point_fmt != NULL) {
			fprintf(log_fd,  ", \"ec_point_fmt\": \"");

			// Jumping to "3" to get past the second length parameter... errrr... why?
			for (arse = 0 ; arse < fp_packet->ec_point_fmt_length; arse++) {
				fprintf(log_fd,  "%.2X", (uint8_t) realec_point_fmt[arse]);
			}
			fprintf(log_fd,  "\"");
			return_code = sqlite3_bind_blob(insert_statement, 19, realec_point_fmt, fp_packet->ec_point_fmt_length, NULL);
		}

		fprintf(log_fd,  " } }\n");

		/* Run the INSERT, I think, ish XXX */
		return_code = sqlite3_step(insert_statement);
		if(SQLITE_DONE != return_code) {
			fprintf(stderr, "A problem occured with the sqlite queue mechanism: %s\n", sqlite3_errmsg(sqlite_db));
		} else {
			sqlite3_finalize(insert_statement);
		}

		/* **************************** */
		/* END OF RECORD - OR SOMETHING */
		/* **************************** */

		/* Write the sample packet out */
		if(output_handle != NULL) {
			pcap_dump((u_char *)output_handle, pcap_header, packet);
		}

		/*
			Setup the new fp_packet for the next incoming packet.  Next call to this function will cause a malloc.
		*/
		fp_packet = NULL;
		// I think that we can lose this
		//extensions_malloc = 0;


}
