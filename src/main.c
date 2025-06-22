//Copyright (C) 2025 Brian William Denton
//Available under the GNU GPLv3 License

#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <locale.h>
#include <errno.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <gnutls/gnutls.h>

//#define BERNTRNSFR_CLIENT_CERTIFICATE

#define BUFFER_SIZE 4096
#define BERNTRNSFR_LINUX_SENDFILE_MAX 0x7ffff000

#define FLAG_TCP_SERVER 0b1
#define FLAG_TLS_SERVER 0b10
#define FLAG_SENDER 0b100
#define FLAG_PIPE 0b1000

#define SERVER_CERTFILE "server.pem"
#define SERVER_KEYFILE "server.key"
#ifdef BERNTRNSFR_CLIENT_CERTIFICATE
#define CLIENT_CERTFILE "client.pem"
#define CLIENT_KEYFILE "client.key"
#endif

#define TLS_PRIORITY_STRING "NONE:+VERS-TLS1.2:+AES-256-GCM:+DHE-RSA:+ECDHE-RSA:+SHA384:+AEAD:+CTYPE-SRV-X509:+SIGN-RSA-SHA512:+COMP-NULL:+GROUP-ALL"

#ifdef __ORDER_LITTLE_ENDIAN__
#define PIPE_STR 0x002d
#else
#define PIPE_STR 0x2d00
#endif

#define MYPRINT(str) ((void)!write(STDOUT_FILENO, str, sizeof(str) - 1))

unsigned char state = 0;
uint32_t ip;
uint16_t port;
uint64_t size;
int fd;
int sock;
int pfd;
int pidfd;
pid_t child;
gnutls_session_t session;
gnutls_certificate_credentials_t mycred;

static inline ssize_t my_recv_waitall(gnutls_session_t session, void *const vbuf, size_t size)
{
	ssize_t gnutlsretval;
	ssize_t x = 0;
	char *buf;

	buf = vbuf;
	do
	{
		gnutlsretval = gnutls_record_recv(session, &buf[x], size-x);
		if (gnutlsretval < 0)
		{
			return gnutlsretval;
		}
		x += gnutlsretval;
	}
	while (((size_t)x) != size);

	return x;
}

static inline ssize_t my_send_waitall(gnutls_session_t session, const void *const vbuf, size_t size)
{
	ssize_t gnutlsretval;
	ssize_t x = 0;
	const char *buf;

	buf = vbuf;
	do
	{
		gnutlsretval = gnutls_record_send(session, &buf[x], size-x);
		if (gnutlsretval < 0)
		{
			return gnutlsretval;
		}
		x += gnutlsretval;
	}
	while (((size_t)x) != size);

	return x;
}

static inline void printusage()
{
        MYPRINT("USAGE:\n\tberntlst ABC IPV4_PEER_ADDRESS PORT {FILE|-} [cmd [args [...]]]\n\n\tABC\n\t\tA = tcp socket \"s\"erver or \"c\"lient\n\t\tB = tls handshake  \"s\"erver or \"c\"lient\n\t\tC = \"s\"end or \"r\"ecieve\n\tIf - is given as a file name, it will execute cmd and read it as a pipe IT WILL NOT READ FROM STDIN LIKE MANY OTHER PROGRAMS RUN WITH -!\n");
}

static inline void setupsockstorage(struct sockaddr_storage *sas, uint32_t i, uint16_t p)
{
	((struct sockaddr_in*)sas)->sin_family = AF_INET;
	((struct sockaddr_in*)sas)->sin_addr.s_addr = i;
	#ifdef __ORDER_LITTLE_ENDIAN__
	((struct sockaddr_in*)sas)->sin_port = __builtin_bswap16(p);
	#else
	((struct sockaddr_in*)sas)->sin_port = p;
	#endif

	return;
}

static inline void setupsocket()
{
	int s;
	int myerrno;
	int ssopt;
	struct sockaddr_storage listener = {0};
	struct sockaddr_storage peer = {0};
	socklen_t ssize;

	s = socket(AF_INET, SOCK_CLOEXEC | SOCK_STREAM, 0);
	if (s == -1)
	{
		myerrno = errno;
		perror("socket()");
		exit(myerrno);
	}

	//on linux-6.5.5. these are inhereted after accept()
	//also the kernel's broken rt_tos2priority() function will
	//be fine with the IPTOS_DSCP_LE so there is no need
	//to setsockopt(SO_PRIORITY) (btw priority IS NOT inhereted)
	//I plan on having the default be IPTOS_DSCP_LE
	//bug me if you actually plan to use this server and don't like
	//that behaviour
	ssopt = IPTOS_DSCP_LE;
	if (setsockopt(s, IPPROTO_IP, IP_TOS, &ssopt, sizeof(int)) == -1)
	{
		myerrno = errno;
		perror("IP_TOS (DSCP) setsockopt() failed");
		exit(myerrno);
	}
	if (state & FLAG_TCP_SERVER)
	{
		ssopt = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &ssopt, sizeof(int)) == -1)
		{
			myerrno = errno;
		        perror("SO_REUSEADDR setsockopt() failed");
			exit(myerrno);
		}
	}

	if (state & FLAG_TCP_SERVER)
	{
		setupsockstorage(&listener, 0, port);
		if (bind(s, (struct sockaddr*) &listener, sizeof(struct sockaddr_storage)) == -1)
		{
			myerrno = errno;
			perror("bind()");
			exit(myerrno);
		}

		if (listen(s, 1024) == -1)
		{
			myerrno = errno;
			perror("listen()");
			exit(myerrno);
		}

		while (1)
		{
			ssize = sizeof(struct sockaddr_storage);
			sock = accept4(s, (struct sockaddr*) &peer, &ssize, SOCK_CLOEXEC);
			if (sock == -1)
			{
				if (errno == ECONNABORTED)
				{
					continue;
				}
				myerrno = errno;
				perror("accept()");
				_exit(myerrno);
			}
			if (((struct sockaddr_in*)&peer)->sin_addr.s_addr == ip)
			{
				close(s);
				return;
			}
		        MYPRINT("got connection from non-peer!\n");
			close(sock);
		}
	}
	else
	{
		sock = s;
		setupsockstorage(&peer, ip, port);
		if (connect(sock, (struct sockaddr*) &peer, sizeof(struct sockaddr_storage)))
		{
			myerrno = errno;
			perror("connect()");
			_exit(myerrno);
		}
		return;
	}
	__builtin_unreachable();
}

static inline void setupfileinput(const char *const fstr)
{
	int myerrno;
	struct stat fst;

	fd = open(fstr, O_RDONLY);
	if (fd == -1)
	{
		myerrno = errno;
		perror("input file open()");
		_exit(myerrno);
	}

	if (fstat(fd, &fst))
	{
		myerrno = errno;
		perror("input file fstat()");
		_exit(myerrno);
	}

	size = fst.st_size;
}

static inline void setupfileoutput(const char *const fstr)
{
	int myerrno;

	fd = open(fstr, O_WRONLY | O_EXCL | O_CREAT, 0644);
	if (fd == -1)
	{
		myerrno = errno;
		perror("output file open()");
		_exit(myerrno);
	}

	if (size)
	{
		if (fallocate(fd, 0, 0, size))
		{
			myerrno = errno;
			perror("output file fallocate()");
			_exit(myerrno);
		}
	}
}


void setuppipe(int argc, char *argv[])
{
	int myerrno;
	pid_t p;
	int pfds[2];
	char **cmd;
	struct clone_args cargs = {0};
	int x;

	if (pipe(pfds))
	{
		myerrno = errno;
		perror("pipe()");
		_exit(myerrno);
	}

	cargs.flags = CLONE_PIDFD;
	cargs.pidfd = (__u64)&pidfd;
        p = syscall(SYS_clone3, &cargs, sizeof(struct clone_args));
	if (p < 0)
	{
		myerrno = errno;
		perror("clone3()");
		_exit(myerrno);
	}
	if (!p)
	{
		close(pfds[0]);
		if (dup2(pfds[1], STDOUT_FILENO) != STDOUT_FILENO)
		{
			myerrno = errno;
			perror("dup2()");
			_exit(myerrno);
		}
		close(pfds[1]);
		cmd = __builtin_alloca(sizeof(char*) * (1 + (argc - 5)));
		x = 5;
		while (x != argc)
		{
			cmd[x-5] = argv[x];
			x++;
		}
		cmd[x-5] = NULL;
		execvp(argv[5], cmd);
		myerrno = errno;
		perror("execvp()");
		_exit(myerrno);
	}
	close(pfds[1]);
	pfd = pfds[0];
	child = p;
}

static inline char *exittypestr(unsigned long t)
{
	switch (t)
	{
	case CLD_EXITED:
		return "Process voluntarily exited";
	case CLD_KILLED:
		return "Process killed by signal!";
	case CLD_DUMPED:
		return "Process killed by signal! Core dumped!";
	case CLD_STOPPED:
		return "Process stoped by signal";
	case CLD_TRAPPED:
		return "Process is being traced and has been trapped";
	case CLD_CONTINUED:
		return "Process has been continued";
	default:
		return "ERROR UNKNOWN EXIT CAUSE";
	}
}

static inline void spipe()
{
	int myerrno;
	char *buf;
	siginfo_t si;
	ssize_t retval;
	ssize_t gnutlsretval;
	ssize_t totsent = 0;

	size = 0;
	gnutlsretval = my_send_waitall(session, &size, sizeof(uint64_t));
	if (gnutlsretval <= 0)
	{
	        printf("my_send_waitall(): %s\n", gnutls_strerror_name(gnutlsretval));
		_exit(1);
	}

	buf = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
	{
		myerrno = errno;
		perror("mmap()");
		_exit(myerrno);
	}
	while (1)
	{
		retval = read(pfd, buf, BUFFER_SIZE);
		if (retval < 0)
		{
			myerrno = errno;
			perror("pipe read()");
			_exit(myerrno);
		}
		if (!retval)
		{
			MYPRINT("Pipe closed.\nWaiting for the process to exit...");
			if (waitid(P_PIDFD, pidfd, &si, WEXITED))
			{
				myerrno = errno;
				perror("waitid()");
				_exit(myerrno);
			}
			printf(" done!\n\tChild exit type: %s\n\tChild exit code: %i\nSent %'li bytes\n", exittypestr(si.si_code), si.si_status, totsent);
			close(pidfd);
			do
			{
				gnutlsretval = gnutls_bye(session, GNUTLS_SHUT_RDWR);
			}
			while (gnutlsretval == GNUTLS_E_AGAIN);
			close(sock);
			_exit(0);
		}
		gnutlsretval = my_send_waitall(session, buf, retval);
		if (gnutlsretval != retval)
		{
		        printf("gnutls send() failed %s\n", gnutls_strerror_name(gnutlsretval));
			_exit(1);
		}
		totsent += gnutlsretval;
	}
}

static inline void setupstate(const char * const instr)
{
	if (__builtin_strlen(instr) != 3)
	{
		printusage();
		_exit(EINVAL);
	}

	if (instr[0] == 's')
	{
		state |= FLAG_TCP_SERVER;
	}
	else if (instr[0] != 'c')
	{
		printusage();
		_exit(EINVAL);
	}

	if (instr[1] == 's')
	{
		state |= FLAG_TLS_SERVER;
	}
	else if (instr[1] != 'c')
	{
		printusage();
		_exit(EINVAL);
	}

	if (instr[2] == 's')
	{
		state |= FLAG_SENDER;
	}
	else if (instr[2] != 'r')
	{
		printusage();
		_exit(EINVAL);
	}

	return;
}

static inline void setupaddress(const char *const addr, const char *const ports)
{
	unsigned long iport;
	char *endptr;

	if (!inet_pton(AF_INET, addr, &ip))
	{
		MYPRINT("Failed to parse ipv4 address\n");
	        _exit(EINVAL);
	}

	iport = strtoul(ports, &endptr, 0);
	if ((*endptr) || (iport > 0xffff))
	{
		MYPRINT("bad port number!\n");
	        _exit(EINVAL);
	}
	port = iport;
}

static inline void setuptls()
{
	int gnutlsretval;
	int certtype;
	unsigned certstatus;
	gnutls_datum_t certstr;

	if (gnutls_global_init())
	{
		MYPRINT("failed gnutls_global_init()\n");
	        _exit(1);
	}
	if (gnutls_certificate_allocate_credentials(&mycred))
	{
	        MYPRINT("gnutls_certificate_allocate_credentials() failed\n");
	        _exit(1);
	}
	////////////////////////////////////////////////////////////
	if (state & FLAG_TLS_SERVER)
	{
		if (gnutls_certificate_set_x509_key_file(mycred, SERVER_CERTFILE, SERVER_KEYFILE, GNUTLS_X509_FMT_PEM))
		{
			puts("gnutls_certificate_set_x509_key_file() failed");
		        _exit(1);
		}
		#ifdef BERNTRNSFR_CLIENT_CERTIFICATE
		if (gnutls_certificate_set_x509_trust_file(/*peercred*/mycred, CLIENT_CERTFILE, GNUTLS_X509_FMT_PEM) != 1)
		{
			puts("gnutls_certificate_set_x509_trust_file() failed");
		        _exit(1);
		}
		#endif
	}
	else
	{
		#ifdef BERNTRNSFR_CLIENT_CERTIFICATE
		if (gnutls_certificate_set_x509_key_file(mycred, CLIENT_CERTFILE, CLIENT_KEYFILE, GNUTLS_X509_FMT_PEM))
		{
			puts("gnutls_certificate_set_x509_key_file() failed");
		        _exit(1);
		}
		#endif
		if (gnutls_certificate_set_x509_trust_file(/*peercred*/mycred, SERVER_CERTFILE, GNUTLS_X509_FMT_PEM) != 1)
		{
			puts("gnutls_certificate_set_x509_trust_file() failed");
		        _exit(1);
		}
	}
	////////////////////////////////////////////////////////////
	if (gnutls_init(&session, (state & FLAG_TLS_SERVER) ? GNUTLS_SERVER : GNUTLS_CLIENT))
	{
	        MYPRINT("gnutls_init() failed\n");
	        _exit(1);
	}
	////////////////////////////////////////////////////////////
	if (gnutls_priority_set_direct(session, TLS_PRIORITY_STRING, NULL))
	{
		puts("gnutls_priority_set_direct() failed");
	        _exit(1);
	}
	if (gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, mycred))
	{
		puts("gnutls_credentials_set() failed");
	        _exit(1);
	}
	////////////////////////////////////////////////////////////
	if (state & FLAG_TLS_SERVER)
	{
		#ifdef BERNTRNSFR_CLIENT_CERTIFICATE
		gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
		gnutls_certificate_send_x509_rdn_sequence(session, 1);
		gnutls_session_set_verify_cert(session, NULL, 1);
		#endif
	}
	else
	{
		gnutls_session_set_verify_cert(session, NULL, 1);
	}
	gnutls_transport_set_int(session, sock);

	////////////////////////////////////////////////////////////
	do
	{
		gnutlsretval = gnutls_handshake(session);
	}
	while ((gnutlsretval == GNUTLS_E_INTERRUPTED) || (gnutlsretval == GNUTLS_E_AGAIN));

	if (gnutlsretval < 0)
	{
		printf("handshake failed %s\n", gnutls_strerror_name(gnutlsretval));
		if (gnutlsretval == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR)
		{
			certtype = gnutls_certificate_type_get(session);
			certstatus = gnutls_session_get_verify_cert_status(session);
			if (gnutls_certificate_verification_status_print(certstatus, certtype, &certstr, 0))
			{
				puts("gnutls_certificate_verification_status_print() failed");
			        _exit(1);
			}
			puts((char *)certstr.data);
			gnutls_free(certstr.data);
		        _exit(1);
		}
	        _exit(1);
	}
}

static inline void rfile(const char *const fname)
{
	int myerrno;
	char *buf;
	ssize_t gnutlsretval;
	size_t totrecv = 0;

	if (my_recv_waitall(session, &size, sizeof(uint64_t)) <= 0)
	{
		printf("my_recv_waitall(): %s\n", gnutls_strerror_name(gnutlsretval));
		_exit(1);
	}
	#ifdef __ORDER_LITTLE_ENDIAN__
	size = __builtin_bswap64(size);
	#endif
	setupfileoutput(fname);

	buf = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
	{
		myerrno = errno;
		perror("mmap()");
		_exit(myerrno);
	}
	while (1)
	{
		gnutlsretval = gnutls_record_recv(session, buf, BUFFER_SIZE);
		if (gnutlsretval < 0)
		{
			printf("gnutls_record_recv(): %s\n", gnutls_strerror_name(gnutlsretval));
			_exit(1);
		}
		if (gnutlsretval == 0)
		{
			printf("Got EOF from peer. Received %'li bytes total\n", totrecv);
			break;
		}
		if (write(fd, buf, gnutlsretval) != gnutlsretval)
		{
			myerrno = errno;
			perror("output file write()");
			_exit(myerrno);
		}
		totrecv += gnutlsretval;
		if (size)
		{
			if (totrecv == size)
			{
				printf("Completed recieving the file, got all %'lu bytes\n", size);
				break;
			}
		}
	}
	do
	{
		gnutlsretval = gnutls_bye(session, GNUTLS_SHUT_RDWR);
	} while (gnutlsretval == GNUTLS_E_AGAIN);

	if (gnutlsretval)
	{
		printf("gnutls_bye(): %s\n", gnutls_strerror_name(gnutlsretval));
		_exit(1);
	}
	close(sock);
	close(fd);
	return;

	_exit(0);
	__builtin_unreachable();
}

static inline void sfile()
{
	ssize_t gnutlsretval;
	ssize_t totsent = 0;
	ssize_t cursend;

	#ifdef __ORDER_LITTLE_ENDIAN__
	size = __builtin_bswap64(size);
	#endif
	gnutlsretval = my_send_waitall(session, &size, sizeof(uint64_t));
	if (gnutlsretval <= 0)
	{
	        printf("my_send_waitall(): %s\n", gnutls_strerror_name(gnutlsretval));
		_exit(1);
	}
	#ifdef __ORDER_LITTLE_ENDIAN__
	size = __builtin_bswap64(size);
	#endif

	while (((size_t)totsent) != size)
	{
		cursend = size - totsent;
		if (cursend > BERNTRNSFR_LINUX_SENDFILE_MAX)
		{
			cursend = BERNTRNSFR_LINUX_SENDFILE_MAX;
		}

		gnutlsretval = gnutls_record_send_file(session, fd, NULL, cursend);
		if (gnutlsretval < 0)
		{
			printf("gnutls_record_send_file(): %s\n", gnutls_strerror_name(gnutlsretval));
			_exit(1);
		}
		totsent += gnutlsretval;
	}
	printf("Completed sending the file, sent all %'lu bytes\n", size);
        do
	{
		gnutlsretval = gnutls_bye(session, GNUTLS_SHUT_RDWR);
	} while (gnutlsretval == GNUTLS_E_AGAIN);

	if (gnutlsretval)
	{
		printf("gnutls_bye(): %s\n", gnutls_strerror_name(gnutlsretval));
		_exit(1);
	}
	close(sock);
	close(fd);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	if (argc < 5)
	{
		printusage();
		return EINVAL;
	}

	setupstate(argv[1]);
	setupaddress(argv[2], argv[3]);

	if (state & FLAG_SENDER)
	{
		if ((*((uint16_t*)argv[4])) == PIPE_STR)
		{
			if (argc < 6)
			{
			        MYPRINT("you must provide a command that whose output will be transmitted!\n");
				return EINVAL;
			}
			state |= FLAG_PIPE;
		}
		else
		{
			setupfileinput(argv[4]);
		}
	}

	MYPRINT("Connecting socket...");
	setupsocket();
	MYPRINT(" done!\nTLS handshake...");
	setuptls();
	MYPRINT(" done!\n\n");
	if (state & FLAG_SENDER)
	{
		if (state & FLAG_PIPE)
		{
			//do pipe
			setuppipe(argc, argv);
			spipe();
		}
		else
		{
			sfile();
		}
	}
	else
	{
		rfile(argv[4]);
	}

	return 0;
}
