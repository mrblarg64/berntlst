//Copyright (C) 2025 Brian William Denton
//Available under the GNU GPLv3 License

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <qos2.h>

#define ERRNO_T DWORD
#define SOCKET_T SOCKET
#define NEWLINE "\r\n"
#define U64_PF "%llu"
#define SSO_CAST (const char*)

QOS_FLOWID qosfid = 0;

HANDLE stdouth;
DWORD bout;
#define FASTPRINT(str) (WriteFile(stdouth, str, sizeof(str) - 1, &bout, NULL))

#define SOCKERROR(str) do {			\
wsaerrno = WSAGetLastError();	\
printf(str " 0x%x" NEWLINE, wsaerrno);	\
ExitProcess(wsaerrno);\
} while (0)

#define CLOSESOCK(fd) (closesocket(fd))

#define FASTEXIT(code) (ExitProcess(code))

#define CLOSEFILE(fd) (CloseHandle(fd))

#define BERNTRNSFR_LINUX_SENDFILE_MAX BUFFER_SIZE

HANDLE fd;
WSADATA wsd;
#else

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

#define ERRNO_T int
#define SOCKET_T int
#define NEWLINE "\n"
#define U64_PF "%'lu"
#define SSO_CAST (void*)
#define FASTPRINT(str) ((void)!write(STDOUT_FILENO, str, sizeof(str) - 1))

#define SOCKERROR(str) do {			\
myerrno = errno;\
perror(str);\
_exit(myerrno);\
} while (0)

#define CLOSESOCK(fd) (close(fd))

#define FASTEXIT(code) (_exit(code))

#define CLOSEFILE(fd) (close(fd))

int fd;

#define BERNTRNSFR_LINUX_SENDFILE_MAX 0x7ffff000

#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <gnutls/gnutls.h>


#define BUFFER_SIZE 40960000

#define FLAG_TCP_SERVER 0b1
#define FLAG_TLS_SERVER 0b10
#define FLAG_SENDER 0b100
#define FLAG_PIPE 0b1000


#define TLS_PRIORITY_STRING "NONE:+VERS-TLS1.2:+AES-256-GCM:+DHE-RSA:+ECDHE-RSA:+SHA384:+AEAD:+CTYPE-SRV-X509:+SIGN-RSA-SHA512:+COMP-NULL:+GROUP-ALL"

#ifdef __ORDER_LITTLE_ENDIAN__
#define PIPE_STR 0x002d
#else
#define PIPE_STR 0x2d00
#endif


unsigned char state = 0;
uint32_t ip;
uint16_t port;
uint64_t size;
SOCKET_T sock;
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
        FASTPRINT("USAGE:" NEWLINE "\tberntlst ABC SERVER_CERT_KEY CLIENT_CERT_KEY IPV4_PEER_ADDRESS PORT {FILE|-} [cmd [args [...]]]" NEWLINE NEWLINE "\tABC" NEWLINE "\t\tA = tcp socket \"s\"erver or \"c\"lient" NEWLINE "\t\tB = tls handshake  \"s\"erver or \"c\"lient" NEWLINE "\t\tC = \"s\"end or \"r\"ecieve" NEWLINE NEWLINE "\tSERVER_CERT_KEY" NEWLINE "\t\t the certificate/key file for the TLS server instance e.g potato = \"potato.key\" (private key) and \"potato.pem\" public certificate, only the TLS server needs private key" NEWLINE NEWLINE "\tCLIENT_CERT_KEY" NEWLINE "\t\tthe certicate/key of the TLS client e.g. garlic = \"garlic.pem\", only the TLS client needs private key if you do not want client authentication this can be replaced with a dash \"-\" (no quotes) to not use client certificates for this transfer (dash must be given on both server and client)" NEWLINE NEWLINE "\tIf - is given as a file name, it will execute cmd and read it as a pipe IT WILL NOT READ FROM STDIN LIKE MANY OTHER PROGRAMS RUN WITH \"-\"!" NEWLINE);
}

static inline void exitbadusage()
{
	#ifdef _WIN32
	ExitProcess(ERROR_INVALID_PARAMETER);
	#else
	_exit(EINVAL);
	#endif
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
	SOCKET_T s;
	ERRNO_T myerrno;
	struct sockaddr_storage listener = {0};
	struct sockaddr_storage peer = {0};
	socklen_t ssize;
	#ifdef _WIN32
	int wsaerrno;
        DWORD ssopt;
	QOS_VERSION qosv;
	HANDLE qosh;
	#else
	int ssopt;
	#endif

	#ifdef _WIN32
	myerrno = WSAStartup(MAKEWORD(2, 2), &wsd);
	if (myerrno)
	{
		printf("failed WSAStartup() ecode 0x%lx" NEWLINE, myerrno);
		ExitProcess(myerrno);
	}

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		SOCKERROR("socket()");
	}
	#else


	s = socket(AF_INET, SOCK_CLOEXEC | SOCK_STREAM, 0);
	if (s == -1)
	{
		SOCKERROR("socket()");
	}
	#endif

	#ifdef _WIN32
        qosv.MajorVersion = 1;
        qosv.MinorVersion = 0;
	if (!QOSCreateHandle(&qosv, &qosh))
	{
		myerrno = GetLastError();
		printf("QOSCreateHandle() failed 0x%lx" NEWLINE, myerrno);
	        FASTEXIT(myerrno);
	}
	#else
	//on linux-6.5.5. these are inhereted after accept()
	//also the kernel's broken rt_tos2priority() function will
	//be fine with the IPTOS_DSCP_LE so there is no need
	//to setsockopt(SO_PRIORITY) (btw priority IS NOT inhereted)
	//I plan on having the default be IPTOS_DSCP_LE
	//bug me if you actually plan to use this server and don't like
	//that behaviour
	ssopt = IPTOS_DSCP_LE;
	if (setsockopt(s, IPPROTO_IP, IP_TOS, SSO_CAST &ssopt, sizeof(int)) == -1)
	{
	        SOCKERROR("IP_TOS (DSCP) setsockopt() failed");
	}
	#endif
	if (state & FLAG_TCP_SERVER)
	{
		ssopt = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, SSO_CAST &ssopt, sizeof(int)) == -1)
		{
		        SOCKERROR("SO_REUSEADDR setsockopt() failed");
		}
	}

	if (state & FLAG_TCP_SERVER)
	{
		setupsockstorage(&listener, 0, port);
		if (bind(s, (struct sockaddr*) &listener, sizeof(struct sockaddr_storage)) == -1)
		{
		        SOCKERROR("bind()");
		}

		if (listen(s, 1024) == -1)
		{
		        SOCKERROR("listen()");
		}

		while (1)
		{
			ssize = sizeof(struct sockaddr_storage);
			#ifdef _WIN32
			sock = accept(s, (struct sockaddr*) &peer, &ssize);
			if (sock == INVALID_SOCKET)
			{
				wsaerrno = WSAGetLastError();
				if (wsaerrno == WSAECONNABORTED)
				{
					continue;
				}
			        printf("accept() 0x%x" NEWLINE, wsaerrno);
				ExitProcess(wsaerrno);
			}
			#else
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
			#endif
			if (((struct sockaddr_in*)&peer)->sin_addr.s_addr == ip)
			{
				//Comment CLOSESOCK() out if you are running on
				//linux in wsl2 and mirrored networking mode
			        CLOSESOCK(s);
				#ifdef _WIN32
				if (!QOSAddSocketToFlow(qosh, sock, NULL, QOSTrafficTypeBackground, QOS_NON_ADAPTIVE_FLOW, &qosfid))
				{
					SOCKERROR("QOSAddSocketToFlow()");
				}
				#endif
				return;
			}
		        FASTPRINT("got connection from non-peer!" NEWLINE);
		        CLOSESOCK(sock);
		}
	}
	else
	{
		sock = s;
		setupsockstorage(&peer, ip, port);
		if (connect(sock, (struct sockaddr*) &peer, sizeof(struct sockaddr_storage)))
		{
		        SOCKERROR("connect()");
		}
		#ifdef _WIN32
		if (!QOSAddSocketToFlow(qosh, sock, NULL, QOSTrafficTypeBackground, QOS_NON_ADAPTIVE_FLOW, &qosfid))
		{
			SOCKERROR("QOSAddSocketToFlow()");
		}
		#endif
		return;
	}

	__builtin_unreachable();
}

static inline void setupfileinput(const char *const fstr)
{
	ERRNO_T myerrno;

	#ifdef _WIN32
	LARGE_INTEGER fsize;

	fd = CreateFile(fstr, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (fd == INVALID_HANDLE_VALUE)
	{
		myerrno = GetLastError();
		printf("CreateFile() failed ecode 0x%lx" NEWLINE, myerrno);
		ExitProcess(myerrno);
	}

	if (!GetFileSizeEx(fd, &fsize))
	{
		myerrno = GetLastError();
		printf("GetLastError() failed ecode 0x%lx" NEWLINE, myerrno);
		ExitProcess(myerrno);
	}

	size = fsize.QuadPart;
	#else
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
	#endif
}

static inline void setupfileoutput(const char *const fstr)
{
	ERRNO_T myerrno;

	#ifdef _WIN32
	LARGE_INTEGER li;

	fd = CreateFile(fstr, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (fd == INVALID_HANDLE_VALUE)
	{
		myerrno = GetLastError();
		printf("CreateFile() failed ecode 0x%lx" NEWLINE, myerrno);
		ExitProcess(myerrno);
	}

	if (size)
	{
		li.QuadPart = size;
		if (!SetFilePointerEx(fd, li, NULL, FILE_BEGIN))
		{
			myerrno = GetLastError();
			printf("SetFilePointerEx() failed ecode 0x%lx" NEWLINE, myerrno);
			ExitProcess(myerrno);
		}

		if (!SetEndOfFile(fd))
		{
			myerrno = GetLastError();
			printf("SetEndOfFile() failed ecode 0x%lx" NEWLINE, myerrno);
			ExitProcess(myerrno);
		}

		li.QuadPart = 0;
		if (!SetFilePointerEx(fd, li, NULL, FILE_BEGIN))
		{
			myerrno = GetLastError();
			printf("SetFilePointerEx() failed ecode 0x%lx" NEWLINE, myerrno);
			ExitProcess(myerrno);
		}
	}
	#else
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
	#endif
}

#ifdef _WIN32
static inline void spipe()
{
}

static inline void setuppipe()
{
}
#else
void setuppipe(int argc, char *argv[])
{
	ERRNO_T myerrno;
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
		cmd = __builtin_alloca(sizeof(char*) * (1 + (argc - 7)));
		x = 7;
		while (x != argc)
		{
			cmd[x-7] = argv[x];
			x++;
		}
		cmd[x-7] = NULL;
		execvp(argv[7], cmd);
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
	ERRNO_T myerrno;
	char *buf;
	siginfo_t si;
	ssize_t retval;
	ssize_t gnutlsretval;
	ssize_t totsent = 0;

	size = 0;
	gnutlsretval = my_send_waitall(session, &size, sizeof(uint64_t));
	if (gnutlsretval <= 0)
	{
	        printf("my_send_waitall(): %s" NEWLINE, gnutls_strerror_name(gnutlsretval));
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
			FASTPRINT("Pipe closed." NEWLINE "Waiting for the process to exit...");
			if (waitid(P_PIDFD, pidfd, &si, WEXITED))
			{
				myerrno = errno;
				perror("waitid()");
				_exit(myerrno);
			}
			printf(" done!" NEWLINE "\tChild exit type: %s" NEWLINE "\tChild exit code: %i" NEWLINE "Sent " U64_PF " bytes" NEWLINE, exittypestr(si.si_code), si.si_status, totsent);
			close(pidfd);
			do
			{
				gnutlsretval = gnutls_bye(session, GNUTLS_SHUT_RDWR);
			}
			while (gnutlsretval == GNUTLS_E_AGAIN);
			CLOSESOCK(sock);
			_exit(0);
		}
		gnutlsretval = my_send_waitall(session, buf, retval);
		if (gnutlsretval != retval)
		{
		        printf("gnutls send() failed %s" NEWLINE, gnutls_strerror_name(gnutlsretval));
			_exit(1);
		}
		totsent += gnutlsretval;
	}
}
#endif

static inline void setupstate(const char * const instr)
{
	if (__builtin_strlen(instr) != 3)
	{
		printusage();
		exitbadusage();
	}

	if (instr[0] == 's')
	{
		state |= FLAG_TCP_SERVER;
	}
	else if (instr[0] != 'c')
	{
		printusage();
		exitbadusage();
	}

	if (instr[1] == 's')
	{
		state |= FLAG_TLS_SERVER;
	}
	else if (instr[1] != 'c')
	{
		printusage();
		exitbadusage();
	}

	if (instr[2] == 's')
	{
		state |= FLAG_SENDER;
	}
	else if (instr[2] != 'r')
	{
		printusage();
		exitbadusage();
	}

	return;
}

static inline void setupaddress(const char *const addr, const char *const ports)
{
	unsigned long iport;
	char *endptr;

	if (!inet_pton(AF_INET, addr, &ip))
	{
		FASTPRINT("Failed to parse ipv4 address" NEWLINE);
	        exitbadusage();
	}

	iport = strtoul(ports, &endptr, 0);
	if ((*endptr) || (iport > 0xffff))
	{
		FASTPRINT("bad port number!" NEWLINE);
	        exitbadusage();
	}
	port = iport;
}

void setuptls(const char *const server, const char *const client)
{
	int gnutlsretval;
	int certtype;
	unsigned certstatus;
	gnutls_datum_t certstr;
	unsigned char serverslen;
	char *serverpem;
	char *serverkey;
	unsigned char clientslen;
	char *clientpem = NULL;
	char *clientkey;


	serverslen = __builtin_strlen(server);
        serverpem = __builtin_alloca(serverslen + (4 + 1));
	serverkey = __builtin_alloca(serverslen + (4 + 1));

	__builtin_memcpy(serverpem, server, serverslen);
	__builtin_memcpy(&serverpem[serverslen], ".pem", 5);

	__builtin_memcpy(serverkey, server, serverslen);
	__builtin_memcpy(&serverkey[serverslen], ".key", 5);

	if ((*((uint16_t*)client)) != PIPE_STR)
	{
		clientslen = __builtin_strlen(client);
	        clientpem = __builtin_alloca(clientslen + (4 + 1));
		clientkey = __builtin_alloca(clientslen + (4 + 1));

		__builtin_memcpy(clientpem, client, clientslen);
		__builtin_memcpy(&clientpem[clientslen], ".pem", 5);

		__builtin_memcpy(clientkey, client, clientslen);
		__builtin_memcpy(&clientkey[clientslen], ".key", 5);
	}
	
	if (gnutls_global_init())
	{
		FASTPRINT("failed gnutls_global_init()" NEWLINE);
	        FASTEXIT(1);
	}
	if (gnutls_certificate_allocate_credentials(&mycred))
	{
	        FASTPRINT("gnutls_certificate_allocate_credentials() failed" NEWLINE);
	        FASTEXIT(1);
	}
	////////////////////////////////////////////////////////////
	if (state & FLAG_TLS_SERVER)
	{
		if (gnutls_certificate_set_x509_key_file(mycred, serverpem, serverkey, GNUTLS_X509_FMT_PEM))
		{
			puts("gnutls_certificate_set_x509_key_file() failed");
		        FASTEXIT(1);
		}
		if (clientpem)
		{
			if (gnutls_certificate_set_x509_trust_file(/*peercred*/mycred, clientpem, GNUTLS_X509_FMT_PEM) != 1)
			{
				puts("gnutls_certificate_set_x509_trust_file() failed");
				FASTEXIT(1);
			}
		}
	}
	else
	{
		if (clientpem)
		{
			if (gnutls_certificate_set_x509_key_file(mycred, clientpem, clientkey, GNUTLS_X509_FMT_PEM))
			{
				puts("gnutls_certificate_set_x509_key_file() failed");
				FASTEXIT(1);
			}
		}
		if (gnutls_certificate_set_x509_trust_file(/*peercred*/mycred, serverpem, GNUTLS_X509_FMT_PEM) != 1)
		{
			puts("gnutls_certificate_set_x509_trust_file() failed");
		        FASTEXIT(1);
		}
	}
	////////////////////////////////////////////////////////////
	if (gnutls_init(&session, (state & FLAG_TLS_SERVER) ? GNUTLS_SERVER : GNUTLS_CLIENT))
	{
	        FASTPRINT("gnutls_init() failed" NEWLINE);
	        FASTEXIT(1);
	}
	////////////////////////////////////////////////////////////
	if (gnutls_priority_set_direct(session, TLS_PRIORITY_STRING, NULL))
	{
		puts("gnutls_priority_set_direct() failed");
	        FASTEXIT(1);
	}
	if (gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, mycred))
	{
		puts("gnutls_credentials_set() failed");
	        FASTEXIT(1);
	}
	////////////////////////////////////////////////////////////
	if ((state & FLAG_TLS_SERVER) && (clientpem))
	{
		gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
		gnutls_certificate_send_x509_rdn_sequence(session, 1);
		gnutls_session_set_verify_cert(session, NULL, 1);
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
		printf("handshake failed %s" NEWLINE, gnutls_strerror_name(gnutlsretval));
		if (gnutlsretval == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR)
		{
			certtype = gnutls_certificate_type_get(session);
			certstatus = gnutls_session_get_verify_cert_status(session);
			if (gnutls_certificate_verification_status_print(certstatus, certtype, &certstr, 0))
			{
				puts("gnutls_certificate_verification_status_print() failed");
			        FASTEXIT(1);
			}
			puts((char *)certstr.data);
			//gnutls_free(certstr.data);
		        FASTEXIT(1);
		}
	        FASTEXIT(1);
	}
}

static inline void rfile(const char *const fname)
{
	ERRNO_T myerrno;
	char *buf;
	ssize_t gnutlsretval;
	size_t totrecv = 0;
	#ifdef _WIN32
	//HANDLE fmap;
	//FILE_DISPOSITION_INFO fdi = 0;
	DWORD written;
	#endif

	gnutlsretval = my_recv_waitall(session, &size, sizeof(uint64_t));
	if (gnutlsretval <= 0)
	{
		printf("my_recv_waitall(): %s" NEWLINE, gnutls_strerror_name(gnutlsretval));
		FASTEXIT(1);
	}
	#ifdef __ORDER_LITTLE_ENDIAN__
	size = __builtin_bswap64(size);
	#endif

	if (size)
	{
		printf("Expecting " U64_PF " bytes..." NEWLINE, size);
	}
	else
	{
	        FASTPRINT("Receiving a file of unknown size..." NEWLINE);
	}
	
	setupfileoutput(fname);

	#ifdef _WIN32
	/* fmap = CreateFileMapping(fd, NULL, PAGE_READWRITE, 0, 0, NULL); */
	/* if (!fmap) */
	/* { */
	/* 	myerrno = GetLastError(); */
	/* 	printf("CreateFileMapping() failed ecode 0x%lx" NEWLINE "Marking file for deletion...", myerrno); */
	/* 	/\* fdi.DeleteFile = 1; *\/ */
	/* 	/\* if (!SetFileInformationByHandle(fd, FileDispositionInfo, &fdi, sizeof(FILE_DISPOSITION_INFO))) *\/ */
	/* 	/\* { *\/ */
	/* 	/\* 	myerrno = GetLastError(); *\/ */
	/* 	/\* 	printf("CreateFileMapping() failed ecode 0x%lx" NEWLINE "Unable to delete!", myerrno); *\/ */
	/* 	/\* } *\/ */
	/* 	/\* CLOSEFILE(fd); *\/ */
	/* 	FASTEXIT(myerrno); */
	/* } */
	/* buf = MapViewOfFile(fmap, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0); */
	/* if (!buf) */
	/* { */
	/* 	myerrno = GetLastError(); */
	/* 	printf("MapViewOfFile() failed ecode 0x%lx" NEWLINE "Marking file for deletion...", myerrno); */
	/* 	/\* fdi.DeleteFile = 1; *\/ */
	/* 	/\* if (!SetFileInformationByHandle(fd, FileDispositionInfo, &fdi, sizeof(FILE_DISPOSITION_INFO))) *\/ */
	/* 	/\* { *\/ */
	/* 	/\* 	myerrno = GetLastError(); *\/ */
	/* 	/\* 	printf("CreateFileMapping() failed ecode 0x%lx" NEWLINE "Unable to delete!", myerrno); *\/ */
	/* 	/\* } *\/ */
	/* 	/\* CLOSEFILE(fd); *\/ */
	/* 	FASTEXIT(myerrno); */
	/* } */
	buf = VirtualAlloc(NULL, BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buf)
	{
		myerrno = GetLastError();
		printf("VirtualAlloc() 0x%lx" NEWLINE, myerrno);
		FASTEXIT(myerrno);
	}
	#else
	buf = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
	{
		myerrno = errno;
		perror("mmap()");
		FASTEXIT(myerrno);
	}
	#endif
	while (1)
	{
		gnutlsretval = gnutls_record_recv(session, buf, BUFFER_SIZE);
		if (gnutlsretval < 0)
		{
			printf("gnutls_record_recv(): %s" NEWLINE, gnutls_strerror_name(gnutlsretval));
			FASTEXIT(1);
		}
		if (gnutlsretval == 0)
		{
			printf("Got EOF from peer. Received " U64_PF " bytes total" NEWLINE, totrecv);
			break;
		}
		#ifdef _WIN32
		if (!WriteFile(fd, buf, gnutlsretval, &written, NULL))
		{
			myerrno = GetLastError();
			printf("WriteFile() failed ecode 0x%lx" NEWLINE, myerrno);
			FASTEXIT(myerrno);
		}
		#else
		if (write(fd, buf, gnutlsretval) != gnutlsretval)
		{
			myerrno = errno;
			perror("output file write()");
			FASTEXIT(myerrno);
		}
		#endif
		totrecv += gnutlsretval;
		if (size)
		{
			if (totrecv == size)
			{
				printf("Completed recieving the file, got all " U64_PF " bytes" NEWLINE, size);
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
		printf("gnutls_bye(): %s" NEWLINE, gnutls_strerror_name(gnutlsretval));
		FASTEXIT(1);
	}
	CLOSESOCK(sock);
	#ifdef _WIN32
	/* if (!UnmapViewOfFile(buf)) */
	/* { */
	/* 	myerrno = GetLastError(); */
	/* 	printf("UnmapViewOfFile() failed ecode 0x%lx" NEWLINE, myerrno); */
	/* } */
	/* CloseHandle(fmap); */
	#endif
	CLOSEFILE(fd);
	return;

	FASTEXIT(0);
	__builtin_unreachable();
}

static inline void sfile()
{
	ssize_t gnutlsretval;
	ssize_t totsent = 0;
	ssize_t cursend;

	#ifdef _WIN32
	ERRNO_T myerrno;
	char *buf;
	DWORD bread;

	buf = VirtualAlloc(NULL, BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buf)
	{
		myerrno = GetLastError();
		printf("VirtualAlloc() 0x%lx" NEWLINE, myerrno);
		FASTEXIT(myerrno);
	}
	#endif

	#ifdef __ORDER_LITTLE_ENDIAN__
	size = __builtin_bswap64(size);
	#endif
	gnutlsretval = my_send_waitall(session, &size, sizeof(uint64_t));
	if (gnutlsretval <= 0)
	{
	        printf("my_send_waitall(): %s" NEWLINE, gnutls_strerror_name(gnutlsretval));
		FASTEXIT(1);
	}
	#ifdef __ORDER_LITTLE_ENDIAN__
	size = __builtin_bswap64(size);
	#endif

	while (((size_t)totsent) != size)
	{
		cursend = size - totsent;
		//this macro is changed for win32
		//not a mistake!
		if (cursend > BERNTRNSFR_LINUX_SENDFILE_MAX)
		{
			cursend = BERNTRNSFR_LINUX_SENDFILE_MAX;
		}

		#ifdef _WIN32
		if (!ReadFile(fd, buf, cursend, &bread, NULL))
		{
			myerrno = GetLastError();
			printf("ReadFile() 0x%lx" NEWLINE, myerrno);
			FASTEXIT(myerrno);
		}
		gnutlsretval = my_send_waitall(session, buf, cursend);
		#else
		gnutlsretval = gnutls_record_send_file(session, fd, NULL, cursend);
		#endif
		if (gnutlsretval <= 0)
		{
			printf("gnutls_record_send_file(): %s" NEWLINE, gnutls_strerror_name(gnutlsretval));
			FASTEXIT(1);
		}
		totsent += gnutlsretval;
	}
	printf("Completed sending the file, sent all " U64_PF " bytes" NEWLINE, size);
        do
	{
		gnutlsretval = gnutls_bye(session, GNUTLS_SHUT_RDWR);
	} while (gnutlsretval == GNUTLS_E_AGAIN);

	if (gnutlsretval)
	{
		printf("gnutls_bye(): %s" NEWLINE, gnutls_strerror_name(gnutlsretval));
		FASTEXIT(1);
	}
	CLOSESOCK(sock);
        CLOSEFILE(fd);
}

int main(int argc, char *argv[])
{
	#ifdef _WIN32
	ERRNO_T myerrno;

	stdouth = GetStdHandle(STD_OUTPUT_HANDLE);
	if (stdouth == INVALID_HANDLE_VALUE)
	{
		myerrno = GetLastError();
		printf("failed GetStdHandle(), ecode 0x%lx" NEWLINE, myerrno);
		return myerrno;
	}
	#else
	setlocale(LC_ALL, "");
	#endif

	if (setvbuf(stdout, NULL, _IONBF, 0))
	{
		puts("setvbuf() failed");
	}

	if (argc < 7)
	{
		printusage();
		exitbadusage();
	}

	setupstate(argv[1]);
	setupaddress(argv[4], argv[5]);

	if (state & FLAG_SENDER)
	{
		if ((*((uint16_t*)argv[6])) == PIPE_STR)
		{
			#ifdef _WIN32
			FASTPRINT("Pipe sources are not implemented on Windows" NEWLINE);
			return ERROR_CALL_NOT_IMPLEMENTED;
			#endif
			if (argc < 8)
			{
			        FASTPRINT("you must provide a command that whose output will be transmitted!" NEWLINE);
				return EINVAL;
			}
			state |= FLAG_PIPE;
		}
		else
		{
			setupfileinput(argv[6]);
		}
	}

	FASTPRINT("Connecting socket...");
	setupsocket();
	FASTPRINT(" done!" NEWLINE "TLS handshake...");
	setuptls(argv[2], argv[3]);
	FASTPRINT(" done!" NEWLINE NEWLINE);
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
		rfile(argv[6]);
	}

	return 0;
}
