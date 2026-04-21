#pragma once

#include "../Types.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <ws2tcpip.h>

#include <condition_variable>
#include <vector>
#include <algorithm>

enum
{
	SB_SIZE_SMALL = 2 * 8 * 1024,
	SB_SIZE_DEFAULT = 8 * 8 * 1024, /*!< largest value for (unscaled) window */
	SB_SIZE_BIG = 32 * 8 * 1024   
};

enum 
{ 
	SB_SIZE = 
	//SB_SIZE_SMALL
	//SB_SIZE_DEFAULT 
	SB_SIZE_BIG
}; /*!< Define for large buffer test */


class inet_os;
class inpcb;
class protosw;

/*!
    \namespace	netlab

    \brief	the main netlab namespace
*/
namespace netlab
{


	/*!
		\class	socket

		\brief
		Kernel structure per socket. Contains send and receive buffer queues, handle on protocol
		and pointer to protocol private data and error information.
		*/
	class L5_socket {
	public:
		typedef	int32_t						pid_t;		/* process id */
		typedef	u_long						tcp_seq;



		/*!
			\struct	sockbuf

			\brief	Variables for socket buffering. The buffer is a circular array that can be initiated to any size, and resize in runtime.
			The circular array is an STL container and supports STL container operations and iterators.
		*/
		struct sockbuf;

		/*!
		    \struct	upcallarg
		
		    \brief	For upcall arguments.
		*/
		struct upcallarg { };

		/*!
		    \fn	L5_socket::L5_socket(inet_os &inet)
		
		    \brief	Constructor.
		
		    \param [in,out]	inet	The inet.
		*/
		L5_socket(inet_os &inet) : inet(inet) 
		{
            this->so_type = 0;
            this->so_options = 0;
            this->so_linger = 0;
            this->so_state = 0;

            this->so_pcb = nullptr;            
            this->so_proto = nullptr;
  
            this->so_head = nullptr;     
            this->so_q0 = nullptr;     
            this->so_q = nullptr;       
            this->so_q0len = 0;    
            this->so_qlen = 0;     
            this->so_qlimit = 0;    
            this->so_timeo = 0;    

            this->so_error = 0; 
            this->so_pgid = 0;     
            this->so_oobmark = 0; 

            this->so_tpcb = nullptr; /*!< Wisc. protocol control block XXX */

            this->upcall = false;           /*!< true to upcall */
            this->so_upcallarg = nullptr;   /*!< Arg for above */

       
		}

		/*!
		    \fn	L5_socket::L5_socket(_In_ int af, _In_ int type, _In_ int protocol, inet_os &inet)
		
		    \brief
		    The socket system call creates a new socket and associates it with a protocol as
		    specified by the domain, type, and protocol arguments specified by the process. The
		    function allocates a new descriptor, which identifies the socket in future system
		    calls, and returns the descriptor to the process. Before each system call a structure
		    is defined to describe the arguments passed from the process to the kernel. In this
		    case, the arguments are passed within a socket_args structure. All the socket-layer
		    system calls have three arguments: p, a pointer to the proc structure for the calling
		    process; uap, a pointer to a structure containing the arguments passed by the process
		    to the system call; and retval, a value-result argument that points to the return
		    value for the system call. Normally, we ignore the p and ret val arguments and refer
		    to the contents of the structure pointed to by uap as the arguments to the system
		    call.
		
		    \param	af				The af.
		    \param	type			The type.
		    \param	protocol		The protocol.
		    \param [in,out]	inet	The inet.
		*/
		L5_socket(_In_ int af, _In_ int type, _In_ int protocol, inet_os &inet) : L5_socket(inet) { }
		
		/*!
		    \pure virtual void L5_socket::bind(_In_ const struct sockaddr *addr, _In_ int addr_len) = 0;
		
		    \brief
		    The bind system call associates a local network transport address with a socket. A
		    process acting as a client usually does not care what its local address is. In this
		    case, it isn't necessary to call bind before the process attempts to communicate; the
		    kernel selects and implicitly binds a local address to the socket as needed. A server
		    process almost always needs to bind to a specific well-known address. If so, the
		    process must call bind before accepting connections (TCP) or receiving datagrams
		    (UDP), because the clients establish connections or send datagrams to the well known
		    address. A socket's foreign address is specified by connect or by one of the write
		    calls that allow specification of foreign addresses (sendto or sendmsg). The
		    arguments to bind (passed within a bind_args structure) are: s, the socket descriptor;
		    name, a pointer to a buffer containing the transport address (e.g., a sockaddr_in
		    structure); and narnelen, the size of the buffer.
		
		    \param	addr		The address.
		    \param	addr_len	Length of the address.
		*/
		virtual void bind(_In_ const struct sockaddr *addr, _In_ int addr_len) = 0;

		/*!
		    \pure	virtual void L5_socket::listen(_In_ int backlog) = 0;
		
		    \brief
		    The listen system call, notifies a protocol that the process is prepared to accept
		    incoming connections on the socket. It also specifies a limit on the number of
		    connections that can be queued on the socket, after which the socket layer refuses to
		    queue additional connection requests. When this occurs, TCP ignores incoming
		    connection requests. Queued connections are made available to the process when it
		    calls accept.
		
		    \param	backlog	The backlog.
		*/
		virtual void listen(_In_ int backlog) = 0;

		/*!
		    \pure virtual netlab::L5_socket* L5_socket::accept(_Out_ struct sockaddr *addr, _Inout_ int *addr_len) = 0;
		
		    \brief
		    After calling listen, a process waits for incoming connections by calling accept,
		    which returns a descriptor that references a new socket connected to a client. The
		    original socket, s, remains unconnected and ready to receive additional connections.
		    accept returns the address of the foreign system if name points to a valid buffer.
		    The connection-processing details are handled by the protocol associated with the
		    socket. For TCP, the socket layer is notified when a connection has been established
		    (i.e., when TCP's three-way handshake has completed). The connection is completed
		    when explicitly confirmed by the process by reading or writing on the socket. The
		    three arguments to accept (in the accept_args structure) are: s, the socket
		    descriptor; name, a pointer to a buffer to be filled in by accept with the transport
		    address of the foreign host; and anamelen, a pointer to the size of the buffer.
		
		    \param [in,out]	addr		If non-null, the address.
		    \param [in,out]	addr_len	If non-null, length of the address.
		
		    \return	null if it fails, else a netlab::L5_socket*.
		*/
		virtual netlab::L5_socket* accept(_Out_ struct sockaddr *addr, _Inout_ int *addr_len) = 0;

		/*!
		    \pure virtual void L5_socket::connect(_In_ const struct sockaddr *name, _In_ int name_len) = 0;
		
		    \brief
		    connect System call: A server process calls the listen and accept system calls to
		    wait for a remote process to initiate a connection. If the process wants to initiate
		    a connection itself (i.e., a client), it calls connect.
		    	For connection-oriented protocols such as TCP, connect establishes a connection to
		    the specified foreign address. The kernel selects and implicitly binds an address to
		    the local socket if the process has not already done so with bind.
		    	For connectionless protocols such as UDP or ICMP, connect records the foreign
		    address for use in sending future datagrams. Any previous foreign address is replaced
		    with the new address.
		    	Figure 15.31 shows the functions called when connect is used for UDP or TCP. The
		    	left side of the figure shows connect processing for connectionless protocols,
		    such as UDP. In this case the protocol layer calls soisconnected and the connect
		    system call returns immediately.
		    	The right side of the figure shows connect processing for connection-oriented
		    	protocols,
		    such as TCP. In this case, the protocol layer begins the connection establishment and
		    calls soisconnecting to indicate that the connection will complete some time in the
		    future. Unless the socket is nonblocking, soconnect calls tsleep to wait for the
		    connection to complete. For TCP, when the three-way handshake is complete, the
		    protocol layer calls soisconnected to mark the socket as connected and then calls
		    wakeup to awaken the process and complete the connect system call. The three
		    arguments to connect (in the connect_args structure) are: s, the socket descriptor;
		    name, a pointer to a buffer containing the foreign address; and namelen, the length
		    of the buffer.
		
		    \param	name		The name.
		    \param	name_len	Length of the name.
		*/
		virtual void connect(_In_ const struct sockaddr *name, _In_ int name_len) = 0;

		/*!
		    \pure	virtual void L5_socket::shutdown(_In_ int how = SD_BOTH) = 0;
		
		    \brief	Shuts down this object and frees any resources it is using.
		
		    \param	how	The how.
		*/
		virtual void shutdown(_In_ int how = SD_BOTH) = 0;

		/*!
		    \pure	virtual L5_socket::~L5_socket() = 0;
		
		    \brief	Destructor, should call soclose.
		*/
		virtual ~L5_socket() = 0;

		/*!
		    \pure virtual void L5_socket::send(std::string uio, size_t chunk = 1024, int flags = 0) = 0;
		
		    \brief
		    Send on a socket. If send must go all at once and message is larger than send
		    buffering, then hard error. Lock against other senders. If must go all at once and
		    not enough room now, then inform user that this would block and do nothing. Otherwise,
		    if nonblocking, send as much as possible. The data to be sent is described by "uio"
		    if nonzero, otherwise by the mbuf chain "top" (which must be null if uio is not).
		    Data provided in mbuf chain must be small enough to send all at once. sosend
		    Function: sosend is one of the most complicated functions in the socket layer. Recall
		    from Figure 16.8 that all five write calls eventually call sosend. It is sosend's
		    responsibility to pass the data and control information to the pr_usrreq function of
		    the protocol associated with the socket according to the semantics supported by the
		    protocol and the buffer limits specified by the socket. sosend never places data in
		    the send buffer; it is the protocol's responsibility to store and remove the data.
		    The interpretation of the send buffer's sb_hiwat and sb_lowat values by sosend
		    depends on whether the associated protocol implements reliable or unreliable data
		    transfer semantics.
		    
		    Reliable Protocol Buffering: For reliable protocols, the send buffer holds both data
		    that has not yet been transmitted and data that has been sent, but has not been
		    acknowledged. sb_cc is the number of bytes of data that reside in the send buffer,
		    and 0 &lt;= sb_cc &lt;= sb_hiwat. Remark:	sb_cc may temporarily exceed sb_hiwat when
		    out-of-band data is sent. It is sosend's responsibility to ensure that there is
		    enough space in the send buffer before passing any data to the protocol layer through
		    the pr_usrreq function. The protocol layer adds the data to the send buffer. sosend
		    transfers data to the protocol in one of two ways: a.	If PR_ATOMIC is set, sosend
		    must preserve the message boundaries between the process and the protocol layer. In
		    this case, sosend waits for enough space to become available to hold the entire
		    message. When the space is available, an mbuf chain containing the entire message is
		    constructed and passed to the protocol in a single call through the pr_usrreq
		    function. RDP and SPP are examples of this type of protocol. b.	If PR_ATOMIC is not
		    set, sosend passes the message to the protocol one mbuf at a time and may pass a
		    partial mbuf to avoid exceeding the high-water mark. This method is used with
		    SOCK_STREAM protocols such as TCP and SOCK_SEQPACKET protocols such as TP4. With TP4,
		    record boundaries are indicated explicitly with the MSG_EOR flag (Figure 16.12), so
		    it is not necessary for the message boundaries to be preserved by sosend. TCP
		    applications have no control over the size of outgoing TCP segments. For example, a
		    message of 4096 bytes sent on a TCP socket will be split by the socket layer into two
		    mbufs with external clusters, containing 2048 bytes each, assuming there is enough
		    space in the send buffer for 4096 bytes. Later, during protocol processing, TCP will
		    segment the data according to the maximum segment size for the connection, which is
		    normally less than 2048. When a message is too large to fit in the available buffer
		    space and the protocol allows messages to be split, sosend still does not pass data
		    to the protocol until the free space in the buffer rises above sb_lowat. For TCP,
		    sb_lowat defaults to 2048 (Figure 16.4), so this rule prevents the socket layer from
		    bothering TCP with small chunks of data when the send buffer is nearly full.
		    
		    Unreliable Protocol Buffering: With unreliable protocols (e.g., UDP), no data is ever
		    stored in the send buffer and no acknowledgment is ever expected. Each message is
		    passed immediately to the protocol where it is queued for transmission on the
		    appropriate network device. In this case, sb_cc is always 0, and sb_hiwat specifies
		    the maximum size of each write and indirectly the maximum size of a datagram. Figure
		    16.4 shows that sb_hiwat defaults to 9216(9x1024) for UDP. Unless the process changes
		    sb_hiwat with the SO_SNDBUF socket option, an attempt to write a datagram larger than
		    9216 bytes returns with an error. Even then, other limitations of the protocol
		    implementation may prevent a process from sending large datagrams. Section 11.10 of
		    Volume 1 discusses these defaults and limits in other TCP /IP implementations.
		    Remark:	9216 is large enough for a NFS write, which often defaults to 8192 bytes of
		    data plus protocol headers.
		    
		    The arguments to sosend are: so, a pointer to the relevant socket; addr, a pointer to
		    a destination address; uio, a pointer to a uio structure describing the I/O buffers
		    in user space; top, an mbuf chain that holds data to be sent; control, an mbuf that
		    holds control information to be sent; and flags, which contains options for this
		    write call. Normally, a process provides data to the socket layer through the uio
		    mechanism and top is null. When the kernel itself is using the socket layer (such as
		    with NFS), the data is passed to sosend as an mbuf chain pointed to by top, and uio
		    is null.
		    	    
		    throws nonzero on error, timeout or signal; callers must check for short counts if
		    EINTR/ERESTART are returned. Data and control buffers are freed on return.
		
		    \param	uio  	The uio.
		    \param	chunk	The chunk.
		    \param	flags	The flags.
		*/
		virtual void send(std::string uio, size_t uio_resid, size_t chunk, int flags) = 0;

		/*!
		    \pure virtual int L5_socket::recv(std::string &uio, size_t uio_resid, size_t chunk = 1024, int flags = MSG_WAITALL) = 0;
		
		    \brief
		    Optimized version of soreceive() for stream (TCP) sockets. XXXAO: (MSG_WAITALL |
		    MSG_PEEK) isn't properly handled.
		    
		    Implement receive operations on a socket. We depend on the way that records are added
		    to the sockbuf by sbappend*.  In particular, each record (mbufs linked through m_next)
		    must begin with an address if the protocol so specifies, followed by an optional mbuf
		    or mbufs containing ancillary data, and then zero or more mbufs of data. In order to
		    avoid blocking network interrupts for the entire time here, we splx() while doing the
		    actual copy to user space. Although the sockbuf is locked, new data may still be
		    appended, and thus we must maintain consistency of the sockbuf during that time.
		    
		    The caller may receive the data as a single mbuf chain by supplying an mbuf **mp0 for
		    use in returning the chain.  The uio is then used only for the count in uio_resid.
		    
		    This function transfers data from the receive buffer of the socket to the buffers
		    specified by the process. Some protocols provide an address specifying the sender of
		    the data, and this can be returned along with additional control information that may
		    be present. Before examining the code, we need to discuss the semantics of a receive
		    operation, out-of-band data, and the organization of a socket's receive buffer.
		    
			Figure 16.32 lists the flags that arc recognized by the kernel during soreceive.
			flags			Description											Reference
			MSG_DONTWAIT	do not wait for resources during this call			Figure 16.38
			MSG_OOB			receive out-of-band data instead of regular data	Figure 16.39
			MSG_PEEK		receive a copy of the data without consuming it		Figure 16.43
			MSG_WAITALL		wait for data to fill buffers before returning		Figure 16.50
			Figure 16.32 recvxxx system calls: flag values passed to kernel.

			recvmsg is the only read system call that returns flags to the process. In the other
			calls, the information is discarded by the kernel before control returns to the process.
			Figure 16.33 lists the flags that recvmsg can set in the msghdr structure.
			msg_flags		Description																Reference
			MSG_CTRUNC		the control information received was larger than the butler provided	Figure 16.31
			MSG_EOR			the data received marks the end of a logical record						Figure 16.48
			MSG_OOB			the buffer(s) contains out-of-band data									Figure 16.45
			MSG_TRUNC		the message received was larger than the buffer(s) provided				Figure 16.51
			Figure 16.33 recvmsg system call: rnsg_flag values returned by kernel.
		    
		    Out-of-Band Data: Out-of-band (OOB) data semantics vary widely among protocols. In
		    general, protocols expedite OOB data along a previously established communication
		    link. The OOB data might not remain in sequence with previously sent regular data.
		    The socket layer supports two mechanisms to facilitate handling OOB data in a
		    protocol-independent way: tagging and synchronization. In this chapter we describe
		    the abstract OOB mechanisms implemented by the socket layer. UDP does not support OOB
		    data. The relationship between TCP's urgent data mechanism and the socket OOB
		    n1echanism is described in the TCP chapters. A sending process tags data as OOB data
		    by setting the MSG_OOB flag in any of the sendxxx calls. sosend passes this
		    information to the socket's protocol, which provides any special services, such as
		    expediting the data or using an alternate queuing strategy. When a protocol receives
		    OOB data, the data is set aside instead of placing it in the socket's receive buffer.
		    A process receives the pending OOB data by setting the MSG_OOB flag in one of the
		    recvxxx calls. Alternatively, the receiving process can ask the protocol to place OOB
		    data inline with the regular data by setting the SO_OOBINLINB socket option (Section
		    17.3). When SO_OOBINLINE is set, the protocol places incoming OOB data in the receive
		    buffer with the regular data. In this case, MSG_OOB is not used to receive the OOB
		    data. Read calls return either all regular data or all OOB data. The two types are
		    never mixed in the input buffers of a single input system call. A process that uses
		    recvmsg to receive data can examine the MSG_OOB flag to determine if the returned
		    data is regular data or OOB data that has been placed inline. The socket layer
		    supports synchronization of OOB and regular data by allowing the protocol layer to
		    mark the point in the regular data stream at which OOB data was received. The
		    receiver can determine when it has reached this mark by using the SIOCATMARK ioctl
		    command after each read system call. When receiving regular data, the socket layer
		    ensures that only the bytes preceding the mark are returned in a single message so
		    that the receiver does not inadvertently pass the mark. If additional OOB data is
		    received before the receiver reaches the mark, the mark is silently advanced.
		    
		    soreceive has six arguments. so is a pointer to the socket. A pointer to an mbuf to
		    receive address information is returned in *paddr. If mp0 points to an mbuf pointer,
		    soreceive transfers the receive buffer data to an mbuf chain pointed to by *mp0. In
		    this case, the uio structure is used only for the count in uio_resid. If mp0 is null,
		    soreceive copies the data into buffers described by the uio structure. A pointer to
		    the mbuf containing control information is returned in *controlp, and soreceive
		    returns the flags described in Figure 16.33 in *flagsp.
		
		    \param [in,out]	uio	The uio.
		    \param	uio_resid  	The uio resid.
		    \param	chunk	   	The chunk.
		    \param	flags	   	The flags.
		
		    \return	An int.
		*/
		virtual int recv(std::string &uio, size_t uio_resid, size_t chunk, int flags) = 0;

		/*!
		    \fn	virtual void L5_socket::so_upcall(struct upcallarg *arg, int waitf) = 0;
		
		    \brief	Upcall, called for upper layer implemntation.
		
		    \param [in,out]	arg	If non-null, the argument.
		    \param	waitf	   	The waitf.
		*/
		virtual void so_upcall(struct upcallarg *arg, int waitf) = 0;

		inline class protosw** pffindproto(const int family, const int protocol, const int type) const;

		inline class protosw** pffindtype(const int family, const int type) const;
		
		inline std::mutex& print_mutex();
		
		inline std::mutex& splnet();

		
		
		
		short	so_type;		/*!< generic type, see socket.h */
		short	so_options;		/*!< from socket call, see socket.h */
		short	so_linger;		/*!< time to linger while closing */
		short	so_state;		/*!< internal state flags SS_*, below */

		class inpcb		*so_pcb;	/*!< protocol control block */
		class protosw	*so_proto;	/*!< protocol handle */

		/*
		* Variables for connection queueing.
		* Socket where accepts occur is so_head in all subsidiary sockets.
		* If so_head is 0, socket is not related to an accept.
		* For head socket so_q0 queues partially completed connections,
		* while so_q is a queue of connections ready to be accepted.
		* If a connection is aborted and it has so_head set, then
		* it has to be pulled out of either so_q0 or so_q.
		* We allow connections to queue up based on current queue lengths
		* and limit on number of queued connections for this socket.
		*/
		L5_socket *so_head;	/*!< back pointer to accept socket */
		L5_socket *so_q0;		/*!< queue of partial connections */
		L5_socket *so_q;		/*!< queue of incoming connections */
		short	so_q0len;		/*!< partials on so_q0 */
		short	so_qlen;		/*!< number of connections on so_q */
		short	so_qlimit;		/*!< max number queued connections */
		short	so_timeo;		/*!< connection timeout */

		u_short	so_error;		/*!< error affecting connection */
		pid_t	so_pgid;		/*!< pgid for signals */
		u_long	so_oobmark;		/*!< chars to oob mark */

		class inpcb	*so_tpcb;		/*!< Wisc. protocol control block XXX */

		bool upcall;	/*!< true to upcall */
		struct upcallarg *so_upcallarg;		/*!< Arg for above */

		class inet_os			&inet; /*!< The owner os */
	};
}