/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {

  
}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  (void)syscallUUID;
  (void)pid;

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]), std::get<int>(param.params[2]));
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    break;
  case CONNECT:
    this->syscall_connect(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    this->syscall_accept(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;

  // TODO: somehow identify if the packet is for listen or not (maybe use struct to keep track of the state)
  //       case: LISTEN
  //            add packet to listen queue
  //       case: handshake -2
  //            send somehting
  //       case: handshake -3
  //             do something elsew

  last_packet = packet.clone();
  



  std::pair<u_int, u_int> src_addr;
  std::pair<u_int, u_int> dst_addr;
  u_int flags = 0;
  u_int seq_num = 0;
  u_int ack_num = 0;

  // Packet packet_copy = packet.clone();

  readPacket(packet, src_addr, dst_addr, seq_num, ack_num, flags);

  switch(flags) {
    case TH_SYN: {
      std::cout << "\nAT LEAST IT's SYN\n";
      procSYN(src_addr, dst_addr, seq_num, ack_num);
      break;
    }
    case TH_SYN | TH_ACK: {
      std::cout << "\nAT LEAST IT's SYNACK\n";
      procSYNACK(src_addr, dst_addr, seq_num, ack_num);
      break;
    }
    case TH_ACK: {
      std::cout << "\nAT LEAST IT's ACK\n";
      procACK(src_addr, dst_addr, seq_num, ack_num);
    }
  }

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
  int sockfd = createFileDescriptor(pid);

  fd_pid_to_socket_info[{sockfd, pid}] = SocketInfo({sockfd, pid}, TCP_CLOSE);

  returnSystemCall(syscallUUID, sockfd);
  return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
  removeFileDescriptor(pid, sockfd);
  auto address = fd_pid_to_addr[{sockfd, pid}];
  fd_pid_to_addr.erase({sockfd, pid});
  addr_to_fd_pid.erase(address);
  returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, sockaddr* addr, socklen_t addrlen)
{
  std::cout<< "---------------------------SYSCALL BIND \n";
  sockaddr_in* addr_in = (sockaddr_in*) addr;

  std::pair<u_int, u_int> address = { addr_in->sin_addr.s_addr, addr_in->sin_port};
  toHost(address);

  if (fd_pid_to_addr.find({sockfd, pid}) != fd_pid_to_addr.end())
  {
    // found duplicate socket
    returnSystemCall(syscallUUID, -1);
    return;
  }
  if (addr_to_fd_pid.find(address) != addr_to_fd_pid.end())
  {
    // found duplicate ip + port
    returnSystemCall(syscallUUID, -1);
    return;
  }
  if (addr_to_fd_pid.find({INADDR_ANY, ntohs(addr_in->sin_port)}) != addr_to_fd_pid.end())
  {
    // found INADDR_ANY
    returnSystemCall(syscallUUID, -1);
    return;
  }

  fd_pid_to_socket_info[{sockfd, pid}].src_addr = address;

  addr_to_fd_pid[address] = {sockfd, pid};
  fd_pid_to_addr[{sockfd, pid}] = address;

  returnSystemCall(syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, sockaddr* addr, socklen_t* addrlen)
{
  std::cout << "--------------------syscall_getsockname \n";
  sockaddr_in* addr_in = (sockaddr_in *) addr;
  addr_in->sin_family = AF_INET;

  // std::vector<int> key, value;
  // for(std::map<std::pair<int, int>,std::pair<u_int, u_int>>::iterator it = fd_pid_to_addr.begin(); it != fd_pid_to_addr.end(); ++it) {
  //   key.push_back(it->first.first);
  //   value.push_back(it->first.second);
  //   std::cout << "Key1: " << it->first.first << "\n";
  //   std::cout << "Key2: " << it->first.second << "\n";
  // }

  std::pair<u_int, u_int> address =  fd_pid_to_addr[{sockfd, pid}];
  toNetwork(address);
  addr_in->sin_addr.s_addr = address.first;
  addr_in->sin_port = address.second;
  returnSystemCall(syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, sockaddr * addr, socklen_t* addrlen)
{
  SocketInfo socketInfo = fd_pid_to_socket_info[fd_pid_to_addr[{sockfd, pid}]];
  // std::cout<<"\n\n\n getpeername src_addr" <<   socketInfo.src_addr.first << socketInfo.src_addr.second <<"\n\n";
  // std::cout<<"\n\n\n getpeername dst_addr" <<   socketInfo.dst_addr.first << socketInfo.dst_addr.second <<"\n\n";

  this->returnSystemCall(syscallUUID, 0);
  return;
}

// add limit to the number of connections in a queue
// make a struct that will save the queue info
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog_len)
{
  std::cout<<"-------------------SYSCALL LISTEN with backlog: "<< backlog_len <<"\n";
  SocketInfo &socketInfo = fd_pid_to_socket_info[{sockfd, pid}];

  socketInfo.backlog = backlog_len;
  socketInfo.state = TCP_LISTEN;

  returnSystemCall(syscallUUID, 0);
  return;
}

// TODO: not done yet. Decided to do Packets before that
void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, sockaddr * addr, socklen_t* addrlen)
{
  std::cout<<"-------------------------------SYSCALL ACCEPT\n ";

  sockaddr_in* addr_in = (sockaddr_in *) addr;
  addr_in->sin_family = AF_INET;
  addr_in->sin_addr.s_addr = 0;

  SocketInfo &socketInfo = fd_pid_to_socket_info[{sockfd, pid}];
  if (socketInfo.q_packets.size() == 0)
  {
    // no connections in queue, block
    std::cout << "No packets in q, blocking accept\n";
    socketInfo.accept_syscall_id = syscallUUID;
    socketInfo.accept_blocked = true;
    return;
  }

  PacketInfo packetInfo = socketInfo.q_packets.front();
  socketInfo.q_packets.pop();
  
  std::cout<<"HANDLING SYN\n";
  // create new socket and reply with SYNACK
  int new_sockfd = createFileDescriptor(pid);
  SocketInfo new_socketInfo = SocketInfo({new_sockfd, pid}, TCP_CLOSE);

  sockaddr_in * temp_addr = (sockaddr_in *) addr;
  std::pair<u_int, u_int> temp_dst_addr = packetInfo.dst_addr;
  toNetwork(temp_dst_addr);
  temp_addr->sin_addr.s_addr = temp_dst_addr.first;
  temp_addr->sin_port = temp_dst_addr.second;
  
  new_socketInfo.src_addr = packetInfo.dst_addr;
  new_socketInfo.dst_addr = packetInfo.src_addr;
  new_socketInfo.seq_num = 0;
  new_socketInfo.ack_num = packetInfo.seq_num + 1;
  new_socketInfo.state = TCP_SYN_RECV;

  fd_pid_to_socket_info[{new_sockfd, pid}] = new_socketInfo;
  fd_pid_to_addr[{new_sockfd, pid}] = new_socketInfo.dst_addr;
  addr_to_fd_pid[new_socketInfo.dst_addr] = {new_sockfd, pid};

  Packet packet = createPacket(new_socketInfo ,  TH_SYN | TH_ACK );
  
  sendPacket("IPv4", std::move(packet));

  returnSystemCall(syscallUUID, new_sockfd);
  return;
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, sockaddr* addr, socklen_t addrlen)
{
  std::cout <<"-----------------------SYSCALL CONNECT\n";

  SocketInfo &socketInfo = fd_pid_to_socket_info[{sockfd, pid}];
  sockaddr_in * temp_addr_in = (sockaddr_in *) addr;
  socketInfo.dst_addr = {temp_addr_in->sin_addr.s_addr, temp_addr_in->sin_port};

  ipv4_t ip_ipv4 = getIPAddr(0).value();
  u_int ip = (ip_ipv4[0] << 24) | (ip_ipv4[0] << 16) | (ip_ipv4[2] << 8) | (ip_ipv4[3]);
  int port = getRoutingTable(ip_ipv4);

  socketInfo.src_addr = {ip, 1};

  std::cout << "ip and port:" << (u_int) ip << " " << port << "\n";

  fd_pid_to_addr[{sockfd, pid}] = {temp_addr_in->sin_addr.s_addr, temp_addr_in->sin_port};
  addr_to_fd_pid[{temp_addr_in->sin_addr.s_addr, temp_addr_in->sin_port}] = {sockfd, pid};
  
  Packet packet = createPacket(socketInfo ,  TH_SYN);
  
  std::cout << "DST ADDRESS:" << socketInfo.dst_addr.first << " " << socketInfo.dst_addr.second << "\n";
  std::cout << "SRC ADDRESS:" << socketInfo.src_addr.first << " " << socketInfo.src_addr.second << "\n";


  // sendPacket("IPv4", std::move(packet));

  socketInfo.connect_syscall_id = syscallUUID;
  socketInfo.state = TCP_SYN_SENT;
  return;
}

void TCPAssignment::readPacket(Packet packet, std::pair<u_int, u_int>&src_addr, std::pair<u_int, u_int>&dst_addr, uint32_t &seq_num, uint32_t &ack_num, u_int &flags)
{
  packet.readData(26, &dst_addr.first, 4);
  packet.readData(30, &src_addr.first, 4);
  packet.readData(34, &dst_addr.second, 2);
	packet.readData(36, &src_addr.second, 2);
	packet.readData(38, &seq_num, 4);
	packet.readData(42, &ack_num, 4);
  packet.readData(47, &flags, 1);

  seq_num = ntohl(seq_num);
  ack_num = ntohl(ack_num);


  uint tcp_len = packet.getSize() - 34;
  uint8_t* tcp_seg = (uint8_t *) malloc(tcp_len);
  packet.readData(34, tcp_seg, tcp_len);

  uint rec_checksum = 0;
  packet.readData(50, &rec_checksum, 2);

  toHost(src_addr);
  toHost(dst_addr);
}

Packet TCPAssignment::createPacket(SocketInfo &socketInfo, uint flags)
{
  // create packet
  Packet packet = Packet( (size_t) 54);  



  toNetwork(socketInfo.src_addr);
  toNetwork(socketInfo.dst_addr);

  packet.writeData(26, &socketInfo.dst_addr.first, 4);
  packet.writeData(30, &socketInfo.src_addr.first, 4);
  packet.writeData(34, &socketInfo.dst_addr.second, 2);
	packet.writeData(36, &socketInfo.src_addr.second, 2);
  packet.writeData(47, &flags, 1);
  
  uint16_t total_length = htons(20);
	packet.writeData(14 + 2, &total_length, 2);

  u_int32_t temp_seq_num = htonl(socketInfo.seq_num);
  u_int32_t temp_ack_num = htonl(socketInfo.ack_num);

	packet.writeData(38, &temp_seq_num, 4);
	packet.writeData(42, &temp_ack_num, 4);

  uint8_t data_offset = 5 << 4;
	packet.writeData(14 + 20 + 12, &data_offset, 1);
  
  uint16_t checksum = 0;
  packet.writeData(50, &checksum, 2);
  
  uint16_t window_size = htons(51200);
  packet.writeData(48, &window_size, 2);
  
  size_t tcp_len = 20;
  uint8_t* tcp_seg = (uint8_t*) malloc(tcp_len);
  packet.readData(34, tcp_seg, tcp_len);
  
  checksum = ~htons(NetworkUtil::tcp_sum(socketInfo.dst_addr.first, socketInfo.src_addr.first, tcp_seg, tcp_len));

  packet.writeData(50, &checksum, 2);

  toHost(socketInfo.src_addr);
  toHost(socketInfo.dst_addr);

  return packet;
}

void TCPAssignment::procSYN(std::pair<u_int, u_int>src_addr, std::pair<u_int, u_int>dst_addr, uint32_t seq_num, uint32_t ack_num)
{
  std::cout << "---------------------------------PROCSYN \n";
  // check if accept is blocked meaning that I have to
  // if blocked then I have to reply with SYNACK here
  // std::cout << "I will try to find the following address: " << src_addr.first << " " << src_addr.second << "\n";

  std::pair<u_int, u_int> fd_pid = {0, 0};
  if (addr_to_fd_pid.find({INADDR_ANY, src_addr.second}) != addr_to_fd_pid.end())
  {
    fd_pid = addr_to_fd_pid[{INADDR_ANY, src_addr.second}];
  }
  else
  {
    fd_pid = addr_to_fd_pid[src_addr];
  }

  SocketInfo &socketInfo = fd_pid_to_socket_info[fd_pid];

  if (socketInfo.accept_blocked)
  {
    std::cout<<"ACCEPT WAS BLOCKED SENDING SYNACK\n" << "Len of q is " << socketInfo.q_packets.size() << "\n\n";

    // create new socket and reply with SYNACK
    int new_sockfd = createFileDescriptor(fd_pid.second);
    SocketInfo new_socketInfo = SocketInfo({new_sockfd, fd_pid.second}, TCP_CLOSE);

    new_socketInfo.src_addr = dst_addr;
    new_socketInfo.dst_addr = src_addr;
    new_socketInfo.seq_num = 0;
    new_socketInfo.ack_num = seq_num + 1;
    new_socketInfo.state = TCP_SYN_RECV;
    new_socketInfo.backlog = 0;


    // std::cout << "DST ADDRESS:" << new_socketInfo.dst_addr.first << " " << new_socketInfo.dst_addr.second << "\n";
    // std::cout << "SRC ADDRESS:" << new_socketInfo.src_addr.first << " " << new_socketInfo.src_addr.second << "\n";
    // std::cout << "SEQ and ACK:" << new_socketInfo.seq_num << " " << new_socketInfo.ack_num << "\n";

    fd_pid_to_socket_info[{new_sockfd, fd_pid.second}] = new_socketInfo;
    fd_pid_to_addr[{new_sockfd, fd_pid.second}] = new_socketInfo.dst_addr;
    addr_to_fd_pid[new_socketInfo.dst_addr] = {new_sockfd, fd_pid.second};

    Packet packet = createPacket(new_socketInfo ,  TH_SYN | TH_ACK );

    sendPacket("IPv4", std::move(packet));
    
    socketInfo.accept_blocked = false;

    // TODO: send address and also somehow save pointer in socketInfo
    returnSystemCall(socketInfo.accept_syscall_id, new_sockfd);
    return;
  }

  // if it's in listen, then just save that info in queue
  if (socketInfo.state == TCP_LISTEN)
  {
    std::cout<<"SYN after listen \n";
    PacketInfo packetInfo = PacketInfo(src_addr, dst_addr, seq_num, ack_num);
    if (socketInfo.q_packets.size() < socketInfo.backlog)
    {
      socketInfo.q_packets.push(packetInfo);
      return;
    }
    std::cout << "Ignoring packet because backlog limit\n";
    return;
  }

  return;
}

void TCPAssignment::procSYNACK(std::pair<u_int, u_int>src_addr, std::pair<u_int, u_int>dst_addr, uint32_t seq_num, uint32_t ack_num)
{
  std::cout<<"\n\nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n\n";
  return; 
}

void TCPAssignment::procACK(std::pair<u_int, u_int>src_addr, std::pair<u_int, u_int>dst_addr, uint32_t seq_num, uint32_t ack_num)
{
  
  return;
}


} // namespace E
