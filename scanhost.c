/**
 * @author Ricardo Román <reroman4@gmail.com>
 * @file scanhost.c
 *
 * Un simple escaner de hosts conectados utilizando los protocolos
 * ICMP y ARP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

/** Define el tipo de escáner */
typedef enum{
	ARPSocket,
	ICMPSocket
}SocketType;

/** Almacena la información de la interfaz de red a utilizar */
typedef struct{
	int ifindex;
	struct in_addr ip;
	struct in_addr netmask;
	struct ether_addr mac;
}LocalData;

/** Cuerpo del mensaje ARP sobre Ethernet */
typedef struct{
	struct ether_addr ar_sha;
	struct in_addr ar_sip;
	struct ether_addr ar_tha;
	struct in_addr ar_tip;
}__attribute__((__packed__)) Eth_ARP;

#define INET_ALEN		4
#define ETHARPFRAME_LEN sizeof(struct arphdr) + \
						sizeof(Eth_ARP)

/**
 * Obtiene la información local de una interfaz de red.
 * @param dst Estructura donde se almacenará el resultado.
 * @param ifname Nombre de la interfaz de red.
 * @return 0 en caso de éxito, -1 en caso de error.
 */
int loadLocalData( LocalData *dst, const char *ifname )
{
	struct ifreq nic;
	int sock = socket( AF_INET, SOCK_DGRAM, 0 );

	strncpy( nic.ifr_name, ifname, IFNAMSIZ-1 );
	nic.ifr_name[IFNAMSIZ-1] = '\0';

	// ïndice
	if( ioctl( sock, SIOCGIFINDEX, &nic ) < 0 ){
		close( sock );
		return -1;
	}
	dst->ifindex = nic.ifr_ifindex;

	// Dirección IP asignada
	if( ioctl( sock, SIOCGIFADDR, &nic ) < 0 ){
		close( sock );
		return -1;
	}
	memcpy( &dst->ip, nic.ifr_addr.sa_data + 2, INET_ALEN );

	// Dirección MAC
	if( ioctl( sock, SIOCGIFHWADDR, &nic ) < 0 ){
		close( sock );
		return -1;
	}
	memcpy( &dst->mac, nic.ifr_hwaddr.sa_data, ETH_ALEN );

	// Máscara de subred
	if( ioctl( sock, SIOCGIFNETMASK, &nic ) < 0 ){
		close( sock );
		return -1;
	}
	memcpy( &dst->netmask, nic.ifr_netmask.sa_data + 2, INET_ALEN ); 
	close( sock );
	return 0;
}

/**
 * Crea un socket para determinado protocolo.
 * @param type Tipo de socket a crear.
 * @param msecs Establece el tiempo máximo para esperar por una
 * respuesta.
 * @return Un identificador con el nuevo socket en caso de éxito,
 * -1 en caso de error.
 */
int createSocket( SocketType type, int msecs )
{
	int sfd;
	struct timeval timer;

	if( type == ICMPSocket )
		sfd = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );
	else
		sfd = socket( AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP) );

	if( sfd < 0 )
		return -1;

	// Establece tiempo máximo para recibir datos
	timer.tv_sec = msecs / 1000;
	timer.tv_usec = msecs % 1000 * 1000;
	if( setsockopt( sfd, SOL_SOCKET, SO_RCVTIMEO, &timer, sizeof(timer) ) < 0 ){
		close( sfd );
		return -1;
	}
	return sfd;
}

/**
 * Calcula el checksum para la cabecera ICMP.
 * @param head Un apuntador a la cabecera ICMP de la cual
 * calcular el checksum.
 * @return El valor del campo checksum.
 */
unsigned short checksum( const struct icmphdr *head )
{
	unsigned short const *p = (unsigned short*) head;
	int len = sizeof(struct icmphdr);
	int res = 0;

	while( len > 1 ){
		res += *p++;
		len -= 2;
	}
	if( len ){
		unsigned short aux = 0;
		*( (unsigned char*)&aux ) = *(unsigned char const*)p;
		res += aux;
	}
	// Agrega los acarreos
	res = (res >> 16) + (res & 0xffff);
	res += (res >> 16);
	return (unsigned short)~res;
}

/**
 * Verifica si un host responde a un mensaje ICMP.
 * @param sfd Socket de tipo ICMPSocket por el cual se envian/reciben
 * los datos.
 * @param ip IP del host a verificar.
 * @return 1 si el host responde el mensaje, 0 en caso contrario y -1
 * en caso de error.
 */
int icmp_isUp( int sfd, struct in_addr ip )
{
	char packet[4096];
	struct sockaddr_in remote;
	static unsigned short seq = 0;
	struct icmphdr *icmph = (struct icmphdr*) packet;
	struct iphdr *iph = (struct iphdr*) packet;
	pid_t pid = getpid();

	// Llena los campos del mensaje ICMP y los datos del destino
	remote.sin_family = AF_INET;
	remote.sin_port = 0;
	remote.sin_addr.s_addr = ip.s_addr;
	icmph->type = ICMP_ECHO;
	icmph->code = 0;
	icmph->checksum = 0;
	icmph->un.echo.id = pid;
	icmph->un.echo.sequence = seq;
	icmph->checksum = checksum( icmph );

	if( sendto( sfd, packet, sizeof(struct icmphdr), 0,
				(struct sockaddr*) &remote, sizeof(remote) ) < 0 )
		return -1;

	// Ciclo para recibir mensajes ICMP
	while( 1 ){
		memset( packet, 0, sizeof(packet) );
		if( recvfrom( sfd, iph, sizeof(packet), 0, NULL, 0 ) <= 0 ){
			seq++;
			return 0;
		}
		icmph = (struct icmphdr*) (packet + (iph->ihl << 2));
		if( icmph->type == ICMP_ECHOREPLY && icmph->un.echo.id == pid 
				&& icmph->un.echo.sequence == seq ){
			seq++;
			return 1;
		}
	}
}

/**
 * Verifica si un host responde un mensaje ARP.
 * @param sfd Un socket de tupo ARPSocket por el cual se envían/reciben
 * los datos.
 * @param data Una estructura que contiene la información de la interfaz
 * de red a utilizar.
 * @param ip IP del host a verificar.
 * @return 1 si el host responde el mensaje, 0 en caso contrario y -1 en
 * caso de error.
 */
int arp_isUp( int sfd, const LocalData *data, struct in_addr ip )
{
	char frame[ETHARPFRAME_LEN];
	struct sockaddr_ll remote;
	struct arphdr *arph = (struct arphdr*) frame;
	Eth_ARP *arpm = (Eth_ARP*) (arph + 1);

	// Llenado del mensaje ARP y los datos de destino
	remote.sll_family = AF_PACKET;
	remote.sll_protocol = htons( ETH_P_ARP );
	remote.sll_ifindex = data->ifindex;
	remote.sll_hatype = 0;
	remote.sll_pkttype = 0;
	remote.sll_halen = ETH_ALEN;
	memset( remote.sll_addr, 0xff, ETH_ALEN );
	arph->ar_hrd = htons( ARPHRD_ETHER );
	arph->ar_pro = htons( ETH_P_IP );
	arph->ar_hln = ETH_ALEN;
	arph->ar_pln = INET_ALEN;
	arph->ar_op = htons( ARPOP_REQUEST );
	memcpy( &arpm->ar_sha, &data->mac, ETH_ALEN );
	arpm->ar_sip.s_addr = data->ip.s_addr;
	memset( &arpm->ar_tha, 0, ETH_ALEN );
	arpm->ar_tip.s_addr = ip.s_addr;

	if( sendto( sfd, frame, ETHARPFRAME_LEN, 0, 
				(struct sockaddr*) &remote, sizeof(remote) ) < 0 )
		return -1;

	// Ciclo para recibir mensajes ARP
	while( 1 ){
		memset( frame, 0, ETHARPFRAME_LEN );
		if( recvfrom( sfd, frame, ETHARPFRAME_LEN, 0, NULL, 0 ) < 0 )
			return 0;

		if( ntohs(arph->ar_op) == ARPOP_REPLY &&
				arpm->ar_sip.s_addr == ip.s_addr )
			return 1;
	}
}

/**
 * Calcula el resultado de incrementar en uno una dirección IP.
 * @param ip IP a partir de la cual se hará el incremento.
 * @return El resultado de ip+1.
 */
struct in_addr ipAddOne( struct in_addr ip )
{
	struct in_addr aux = { ntohl( ip.s_addr ) };
	aux.s_addr++;
	aux.s_addr = htonl( aux.s_addr );
	return aux;
}

/**
 * Intercambia valores de dos dirección IP
 */
void ipSwap( struct in_addr *a, struct in_addr *b )
{
    a->s_addr = a->s_addr ^ b->s_addr;    
    b->s_addr = a->s_addr ^ b->s_addr;
    a->s_addr = a->s_addr ^ b->s_addr;
}

/** Mensaje de ayuda y uso */
#define HELPMSG \
"Simple scanner for connected hosts.\n\n" \
"Usage: %s -i <network interface> [options]\n\n" \
"Options:\n" \
" -p<protocol>\t\tSpecifies the protocol to use. It can be arp or icmp. Default: arp\n" \
" -t<msecs>\t\tMaximum time to wait for a response. Default: 100\n" \
" -r<x.x.x.x[-y.y.y.y]>\tSpecifies the range to scan. Default: All the hosts in the network\n"\
" -h\t\t\tShow this help\n\n"\
"Examples:\n" \
"\t%s -iwlp1s0\n"\
"\t%s -ienp3s0 -picmp -r192.168.1.100-192.168.1.200\n"\
"\t%s -i wlp1s0 -p arp -t 200 -r 192.168.1.24\n"\
"\nBugs: Ricardo Román <reroman4@gmail.com>\n"

volatile int running = 1; ///< Controla el ciclo para el scanner

/** Interrumpe la ejecución del escáner */
void sigint(){
	running = 0;
}

int main( int argc, char **argv )
{
	int waitTime = 100, opt, ups = 0, total;
	SocketType type = ARPSocket;
	LocalData data;
	int sfd;
	struct in_addr first, last;
	char *strFirst = NULL,
		 *strLast = NULL,
		 *interface = NULL,
		 *aux;

	// Parser de parámetros
	while( (opt = getopt( argc, argv, ":i:p:t:r:h" )) != -1 ){
		switch( opt ){
			case 'i':
				interface = optarg;
				break;
			case 'p':
				if( !strcmp( optarg, "arp" ) )
					type = ARPSocket;
				else if( !strcmp( optarg, "icmp" ) )
					type = ICMPSocket;
				else{
					fprintf( stderr, "%s: Unknown protocol\n", optarg );
					return -1;
				}
				break;
			case 't':
				waitTime = strtol( optarg, &aux, 10 );
				if( *aux ){
					fprintf( stderr, "%s: Invalid time\n", optarg );
					return -1;
				}
				break;
			case 'r':
				strFirst = strtok( optarg, "-" );
				strLast = strtok( NULL, "-" );
				break;
			case 'h':
				printf( HELPMSG, *argv, *argv, *argv, *argv );
				return 0;
				break;
			case ':':
				fprintf( stderr, "%s requires an argument. Use -h for help\n", argv[optind-1] );
				return -1;
			default:
				fprintf( stderr, "%s: Option unknown. Use -h for help\n", argv[optind-1] );
				return -1;
		}
	}

	// Valida la interfaz
	if( !interface ){
		fprintf( stderr, "Error: No interface given. Use -h for help\n" );
		return -1;
	}

	// Carga datos locales
	if( loadLocalData( &data, interface ) < 0 ){
		perror( interface );
		return -1;
	}

	// Valida si hay una IP específica
	if( strFirst ){
		if( !inet_aton( strFirst, &first ) ){
			fprintf( stderr, "%s: Invalid address\n", strFirst );
			return -1;
		}
		if( strLast ){ // Valida si hay un rango
			if( !inet_aton( strLast, &last ) ){
				fprintf( stderr, "%s: Invalid address\n", strLast );
				return -1;
			}
			else{
				total = ntohl( last.s_addr ) - ntohl( first.s_addr );
				if( total < 0 ){
					total = -total;
					ipSwap( &first, &last );
				}
				total++;
			}
		}
		else{
			total = 1;
		}
	}
	else{ // Si no... se obtiene el rango a partir de los datos de red locales.
		first.s_addr = data.ip.s_addr & data.netmask.s_addr;
		first = ipAddOne( first );
		last.s_addr = data.ip.s_addr | ~data.netmask.s_addr;
		total = ntohl( last.s_addr ) - ntohl( first.s_addr );
	}

	// Crea socket
	if( (sfd = createSocket( type, waitTime ) ) < 0 ){
		perror( "Failed to create socket" );
		return 2;
	}

	signal( SIGINT, sigint );
	puts( "CTRL-C to stop scanning" );

	// Ciclo para escáner
	for( int i = 1 ; i <= total && running ; i++, first = ipAddOne(first) ){
		printf( "\r(%d%%) Testing %s...", (int)(100.0 / total * i), inet_ntoa(first) );
		fflush( stdout );
		if( first.s_addr == data.ip.s_addr ){
			printf( " (this host)\n" );
			ups++;
		}
		else{
			if( type == ARPSocket )
				switch( arp_isUp( sfd, &data, first )  ){
					case -1:
						perror( " send request" );
						break;
					case 1:
						puts( " is up"  );
						ups++;
				}
			else
				switch( icmp_isUp( sfd, first ) ){
					case -1:
						perror( " send request" );
						break;
					case 1:
						puts( " is up" );
						ups++;
				}
		}
	}
	close( sfd );
	printf( "\n%d hosts up\n", ups );
	return 0;
}
