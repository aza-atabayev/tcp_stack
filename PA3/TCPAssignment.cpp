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

#include <E/E_TimeUtil.hpp>


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
    this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
                       std::get<void *>(param.params[1]),
                       std::get<int>(param.params[2]));
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<void *>(param.params[1]),
                        std::get<int>(param.params[2]));
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

  last_packet = packet.clone();
  
  std::pair<u_int, u_int> my_addr;
  std::pair<u_int, u_int> their_addr;
  u_int flags = 0;
  u_int seq_num = 0;
  u_int ack_num = 0;
  u_int window_size = 0;


  if (!readPacket(packet, my_addr, their_addr, seq_num, ack_num, flags, window_size))
  {
    // wrong checksum
    return;
  }

  std::pair<u_int, u_int> fd_pid = {0, 0};
  if (their_addr_to_fd_pid.find({INADDR_ANY, their_addr.second}) != their_addr_to_fd_pid.end())
  {
    fd_pid = their_addr_to_fd_pid[{INADDR_ANY, their_addr.second}];
  }
  else
  {
    fd_pid = their_addr_to_fd_pid[their_addr];
  }

  SocketInfo &newSocketInfo = fd_pid_to_socket_info[fd_pid]; 

  if (newSocketInfo.last_seq == seq_num)
  {
    return;
  }

  
  // std::cout << "my_addr_to_fd_pid\n";
  // for(auto it = my_addr_to_fd_pid.cbegin(); it != my_addr_to_fd_pid.cend(); ++it)
  // {
  //   std::cout << it->first.first << " " << it->first.second << " " << it->second.first << " " << it->second.second << "\n";
  // }
  // std::cout << "\n";

  // std::cout << "their_addr_to_fd_pid\n";
  // for(auto it = their_addr_to_fd_pid.cbegin(); it != their_addr_to_fd_pid.cend(); ++it)
  // {
  //   std::cout << it->first.first << " " << it->first.second << " " << it->second.first << " " << it->second.second << "\n";
  // }
  // std::cout << "\n";



  if (packet.getSize() > 54)
  {
    receiveBytes(packet, my_addr, their_addr, seq_num);
    return;
  }

  switch(flags) {
    case TH_SYN: {
      procSYN(my_addr, their_addr, seq_num, ack_num);
      break;
    }
    case TH_SYN | TH_ACK: {
      procSYNACK(my_addr, their_addr, seq_num, ack_num);
      break;
    }
    case TH_ACK: {
      procACK(my_addr, their_addr, seq_num, ack_num, window_size);
      break;
    }
    case TH_FIN | TH_ACK: {
      procFINACK(my_addr, their_addr, seq_num, ack_num);
    }
  }

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;

  TimerCommand timerComamnd  = std::any_cast<TimerCommand>(payload);

  switch(timerComamnd.command) {
  case DO_NOTHING: {
    std::cout<<"DO_NOTHING\n";
    throw std::exception();
    break;
  }  
  case DO_RETRANS: {
    // std::cout<<"DO_RETRANS\n";
    sendPacket("IPv4", std::move(timerComamnd.packet));
    timerComamnd.socketInfo.syn_timer_id = addTimer(TimerCommand(DO_RETRANS, timerComamnd.socketInfo, timerComamnd.packet), TimeUtil::makeTime(RTT_TIME, TimeUtil::MSEC));
    break;
  }
  case DO_CLOSE: {

    break;
  }
  }

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
  // std::cout<< "---------------------------syscall_close " << sockfd << " " << pid<< "\n";
  
  SocketInfo &socketInfo = fd_pid_to_socket_info[{sockfd, pid}];

  if (socketInfo.state == TCP_LISTEN || socketInfo.state == TCP_CLOSE)
  {
    implicit_close(syscallUUID, {sockfd, pid});
    return;
  }

  if (socketInfo.state == TCP_CLOSE_WAIT)
  {
    implicit_close(syscallUUID, {sockfd, pid});
    return;
  }

  socketInfo.state = TCP_FIN_WAIT1;
  socketInfo.close_syscall_id = syscallUUID;
  Packet packet = createPacket(socketInfo,  TH_FIN | TH_ACK);
  
  sendPacket("IPv4", std::move(packet));
}

void TCPAssignment::implicit_close(UUID syscallUUID, std::pair<int, int> fd_pid)
{
  // std::cout << "---------------------------------implicit_close " << fd_pid.first << " " << fd_pid.second << "\n";
  
  removeFileDescriptor(fd_pid.second, fd_pid.first);
  SocketInfo &socketInfo = fd_pid_to_socket_info[fd_pid];

  my_addr_to_fd_pid.erase(socketInfo.my_addr);
  their_addr_to_fd_pid.erase(socketInfo.their_addr); 

  fd_pid_to_socket_info.erase(fd_pid);

  returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, sockaddr* addr, socklen_t addrlen)
{
  // std::cout<< "---------------------------SYSCALL BIND " << sockfd << " " << pid <<"\n";
  sockaddr_in* addr_in = (sockaddr_in*) addr;

  std::pair<u_int, u_int> address = { addr_in->sin_addr.s_addr, addr_in->sin_port};
  toHost(address);

  if (fd_pid_to_socket_info.find({sockfd, pid}) != fd_pid_to_socket_info.end())
  {
    if (fd_pid_to_socket_info[{sockfd, pid}].my_addr != std::make_pair((u_int)0, (u_int) 0))
    {
      // std::cout<< "---------------------------found duplicate socket \n";
      returnSystemCall(syscallUUID, -1);
      return;
    }
  }

  if (my_addr_to_fd_pid.find(address) != my_addr_to_fd_pid.end())
  {
    // found duplicate ip + port
    // std::cout<< "---------------------------found duplicate ip + port \n";

    returnSystemCall(syscallUUID, -1);
    return;
  }
  if (my_addr_to_fd_pid.find({INADDR_ANY, ntohs(addr_in->sin_port)}) != my_addr_to_fd_pid.end())
  {
    // found INADDR_ANY
    // std::cout<< "--------------------------- found INADDR_ANY\n";

    returnSystemCall(syscallUUID, -1);
    return;
  }

  fd_pid_to_socket_info[{sockfd, pid}].my_addr = address;

  my_addr_to_fd_pid[address] = {sockfd, pid};

  // for(auto it = addr_to_fd_pid.cbegin(); it != addr_to_fd_pid.cend(); ++it)
  // {
  //   std::cout << it->first.first << " " << it->first.second << " " << it->second.first << " " << it->second.second << "\n";
  // }

  returnSystemCall(syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, sockaddr* addr, socklen_t* addrlen)
{
  // std::cout << "--------------------syscall_getsockname " << sockfd << " " << pid << "\n";
  sockaddr_in* addr_in = (sockaddr_in *) addr;
  addr_in->sin_family = AF_INET;

  // for(auto it = their_addr_to_fd_pid.cbegin(); it != their_addr_to_fd_pid.cend(); ++it)
  // {
  //   std::cout << it->first.first << " " << it->first.second << " " << it->second.first << " " << it->second.second << "\n";
  // }

  SocketInfo socketInfo = fd_pid_to_socket_info[{sockfd, pid}];
  std::pair<u_int, u_int> address = socketInfo.my_addr;

  // std::cout << "getsockname " << address.first << " "<< address.second <<"\n";
  toNetwork(address);
  addr_in->sin_addr.s_addr = address.first;
  addr_in->sin_port = address.second;
  returnSystemCall(syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, sockaddr * addr, socklen_t* addrlen)
{
  // std::cout << "--------------------syscall_getpeername " << sockfd << " "<<pid << "\n";

  sockaddr_in* addr_in = (sockaddr_in *) addr;
  addr_in->sin_family = AF_INET;

  SocketInfo socketInfo = fd_pid_to_socket_info[{sockfd, pid}];

  std::pair<u_int, u_int> address = socketInfo.their_addr;
  toHost(address);
  addr_in->sin_addr.s_addr = address.first;
  addr_in->sin_port = address.second;

  this->returnSystemCall(syscallUUID, 0);
  return;
}

// add limit to the number of connections in a queue
// make a struct that will save the queue info
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog_len)
{
  // std::cout<<"-------------------SYSCALL LISTEN with backlog: "<< backlog_len <<"\n";
  SocketInfo &socketInfo = fd_pid_to_socket_info[{sockfd, pid}];

  socketInfo.backlog = backlog_len;
  socketInfo.state = TCP_LISTEN;

  returnSystemCall(syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, sockaddr * addr, socklen_t* addrlen)
{
  // std::cout<<"-------------------------------SYSCALL ACCEPT " << sockfd << " " << pid << "\n ";

  sockaddr_in* addr_in = (sockaddr_in *) addr;
  addr_in->sin_family = AF_INET;
  addr_in->sin_addr.s_addr = 0;

  SocketInfo &socketInfo = fd_pid_to_socket_info[{sockfd, pid}];
  if (socketInfo.q_fd_pid.size() == 0 )
  {
    if (socketInfo.backlog_fd_pid.size() != 0)
    {
      // std::cout << "Backlog is "<< socketInfo.backlog_fd_pid.size() <<" but q is 0\n";
    }
    // no connections in queue, block
    // std::cout << "No connections in q, blocking accept\n";
    socketInfo.accept_syscall_id = syscallUUID;
    socketInfo.accept_blocked = true;
    return;
  }

  std::pair<int, int> sock_fd_pid = socketInfo.q_fd_pid.front();
  socketInfo.q_fd_pid.pop();
  // std::cout << "Queue size after pop " << socketInfo.q_fd_pid.size() << "\n";

  // std::cout<< "++++++++++++++++++++++++++++++RETURN ACCEPT WITH sockfd for PID " << sock_fd_pid.first << " " << sock_fd_pid.second <<"\n";
  returnSystemCall(syscallUUID, sock_fd_pid.first);
  return;
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, sockaddr* addr, socklen_t addrlen)
{
  // std::cout <<"-----------------------SYSCALL CONNECT\n";

  SocketInfo &socketInfo = fd_pid_to_socket_info[{sockfd, pid}];
  sockaddr_in * temp_addr_in = (sockaddr_in *) addr;
  std::pair<u_int, u_int> dst_address ={temp_addr_in->sin_addr.s_addr, temp_addr_in->sin_port};
  toNetwork(dst_address);
  socketInfo.their_addr= dst_address;

  ipv4_t ip_ipv4 = getIPAddr(0).value();
  u_int ip = (ip_ipv4[0] << 24) | (ip_ipv4[1] << 16) | (ip_ipv4[2] << 8) | (ip_ipv4[3]);
  int port = getRoutingTable(ip_ipv4);
  std::pair<u_int, u_int> src_address = {ip, port};
  // toHost(src_address); this must be commented
  // std::cout << "+++++++++++++++++++++++++++++++++++++++CONNECT IP "<< src_address.first << " "<< src_address.second << "\n";

  socketInfo.my_addr = src_address;

  // std::cout << "ip and port:" << (u_int) ip << " " << port << "\n";

  their_addr_to_fd_pid[dst_address] = {sockfd, pid};
  
  Packet packet = createPacket(socketInfo,  TH_SYN);
  
  sendPacket("IPv4", std::move(packet));
  socketInfo.syn_timer_id = addTimer(TimerCommand(DO_RETRANS, socketInfo, packet), TimeUtil::makeTime(RTT_TIME, TimeUtil::MSEC));

  socketInfo.connect_syscall_id = syscallUUID;
  socketInfo.state = TCP_SYN_SENT;
  return;
}

bool TCPAssignment::readPacket(Packet packet, std::pair<u_int, u_int>&my_addr, std::pair<u_int, u_int>&their_addr, uint32_t &seq_num, uint32_t &ack_num, u_int &flags, u_int &window_size)
{

  packet.readData(26, &their_addr.first, 4);
  packet.readData(30, &my_addr.first, 4);
  packet.readData(34, &their_addr.second, 2);
	packet.readData(36, &my_addr.second, 2);
	packet.readData(38, &seq_num, 4);
	packet.readData(42, &ack_num, 4);
  packet.readData(47, &flags, 1);
  packet.readData(48, &window_size, 2);

  seq_num = ntohl(seq_num);
  ack_num = ntohl(ack_num);

	uint16_t given_checksum = 0;
	packet.readData(14 + 20 + 16, &given_checksum, 2);

	uint16_t null_checksum = 0;
	packet.writeData(14 + 20 + 16, &null_checksum, 2);

  size_t tcp_len = packet.getSize() - 34;
  uint8_t* tcp_seg = (uint8_t *) malloc(tcp_len);
  packet.readData(34, tcp_seg, tcp_len);

  uint16_t cal_checksum = ~htons(NetworkUtil::tcp_sum(their_addr.first, my_addr.first, tcp_seg, tcp_len));

  toHost(my_addr);
  toHost(their_addr);
  return given_checksum == cal_checksum;
}

Packet TCPAssignment::createPacket(SocketInfo &socketInfo, uint flags, int bytes)
{
  // create packet
  Packet packet = Packet( (size_t) 54 + bytes);  

  toNetwork(socketInfo.my_addr);
  toNetwork(socketInfo.their_addr);

  // std::cout << "DST ADDRESS: " << socketInfo.their_addr.first << " " << socketInfo.their_addr.second << "\n";
  // std::cout << "SRC ADDRESS: " << socketInfo.my_addr.first << " " << socketInfo.my_addr.second << "\n";

  packet.writeData(26, &socketInfo.my_addr.first, 4);
  packet.writeData(30, &socketInfo.their_addr.first, 4);
  packet.writeData(34, &socketInfo.my_addr.second, 2);
	packet.writeData(36, &socketInfo.their_addr.second, 2);
  packet.writeData(47, &flags, 1);
  
  uint16_t total_length = htons(20);
	packet.writeData(14 + 2, &total_length, 2);

  // std::cout << "seq and ack num "<<socketInfo.seq_num << " " << socketInfo.ack_num <<"\n";

  // std::cout<< "socket.seq_num acked_bytes not_sent " << socketInfo.seq_num <<" "<<  socketInfo.senderBuffer.acked_bytes << " "<<socketInfo.senderBuffer.not_sent<< "\n";

  if (flags == TH_FIN | TH_ACK)
  {
    socketInfo.next_ack_fin = socketInfo.seq_num + socketInfo.senderBuffer.acked_bytes + socketInfo.senderBuffer.not_sent + 1;
  }
  // socketInfo.next_ack = socketInfo.seq_num + socketInfo.senderBuffer.acked_bytes + socketInfo.senderBuffer.not_sent + 1;

  u_int32_t temp_seq_num = htonl(socketInfo.seq_num + socketInfo.senderBuffer.acked_bytes + socketInfo.senderBuffer.not_sent);
  u_int32_t temp_ack_num = htonl(socketInfo.ack_num);

	packet.writeData(38, &temp_seq_num, 4);
	packet.writeData(42, &temp_ack_num, 4);

  uint8_t data_offset = 5 << 4;
	packet.writeData(46, &data_offset, 1);
  
  uint16_t checksum = 0;
  packet.writeData(50, &checksum, 2);
  
  uint16_t window_size = htons(socketInfo.receiverBuffer.window_size);
  packet.writeData(48, &window_size, 2);
  
  for (int i = 0; i <= bytes; i++)
  {
    packet.writeData(54 + i, &socketInfo.senderBuffer.buf[i], 1);
  }



  size_t tcp_len = 20 + bytes;
  uint8_t* tcp_seg = (uint8_t*) malloc(tcp_len);
  packet.readData(34, tcp_seg, tcp_len);
  
  checksum = ~htons(NetworkUtil::tcp_sum(socketInfo.their_addr.first, socketInfo.my_addr.first, tcp_seg, tcp_len));

  packet.writeData(50, &checksum, 2);

  toHost(socketInfo.my_addr);
  toHost(socketInfo.their_addr);

  return packet;
}

void TCPAssignment::procSYN(std::pair<u_int, u_int>my_addr, std::pair<u_int, u_int>their_addr, uint32_t seq_num, uint32_t ack_num)
{

  std::pair<u_int, u_int> fd_pid = {0, 0};
  if (my_addr_to_fd_pid.find({INADDR_ANY, my_addr.second}) != my_addr_to_fd_pid.end())
  {
    fd_pid = my_addr_to_fd_pid[{INADDR_ANY, my_addr.second}];
  }
  else
  {
    fd_pid = my_addr_to_fd_pid[my_addr];
  }
  // std::cout << "---------------------------------PROCSYN "<< fd_pid.first << " "<< fd_pid.second << "\n";
  SocketInfo &socketInfo = fd_pid_to_socket_info[fd_pid];

  if (socketInfo.state != TCP_LISTEN) return;
  // std::cout <<"q_fd_pid.size() " << socketInfo.q_fd_pid.size() << " backlog len " <<  socketInfo.backlog;
  if (socketInfo.backlog_fd_pid.size() >= socketInfo.backlog) return;
  // create new socket and reply with SYNACK
  int new_sockfd = createFileDescriptor(fd_pid.second);
  SocketInfo new_socketInfo = SocketInfo({new_sockfd, fd_pid.second}, TCP_CLOSE);

  new_socketInfo.my_addr = my_addr;
  new_socketInfo.their_addr = their_addr;
  new_socketInfo.seq_num = 0;
  new_socketInfo.ack_num = seq_num + 1;
  new_socketInfo.state = TCP_SYN_RECV;
  new_socketInfo.backlog = 0;

  fd_pid_to_socket_info[{new_sockfd, fd_pid.second}] = new_socketInfo;
  their_addr_to_fd_pid[new_socketInfo.their_addr] = {new_sockfd, fd_pid.second};

  Packet packet = createPacket(new_socketInfo ,  TH_SYN | TH_ACK );

  sendPacket("IPv4", std::move(packet));

  socketInfo.backlog_fd_pid.push({new_sockfd, fd_pid.second});

}

void TCPAssignment::procSYNACK(std::pair<u_int, u_int>my_addr, std::pair<u_int, u_int>their_addr, uint32_t seq_num, uint32_t ack_num)
{
  // std::cout << "---------------------------------procSYNACK \n";

  // for(auto it = their_addr_to_fd_pid.cbegin(); it != their_addr_to_fd_pid.cend(); ++it)
  // {
  //   std::cout << it->first.first << " " << it->first.second << " " << it->second.first << " " << it->second.second << "\n";
  // }

  std::pair<u_int, u_int> addr = their_addr;
  // toHost(addr); must be commented

  // std::cout << "I will try to find the following src_address: " << addr.first << " " << addr.second << "\n";

  std::pair<u_int, u_int> fd_pid = {0, 0};
  if (their_addr_to_fd_pid.find({INADDR_ANY, addr.second}) != their_addr_to_fd_pid.end())
  {
    fd_pid = their_addr_to_fd_pid[{INADDR_ANY, addr.second}];
  }
  else
  {
    fd_pid = their_addr_to_fd_pid[addr];
  }

  SocketInfo &socketInfo = fd_pid_to_socket_info[fd_pid];
  socketInfo.seq_num++;
  socketInfo.ack_num = seq_num + 1;
  socketInfo.state = TCP_ESTABLISHED;
  cancelTimer(socketInfo.syn_timer_id);

  Packet packet = createPacket(socketInfo, TH_ACK);
  sendPacket("IPv4", std::move(packet));
  

  returnSystemCall(socketInfo.connect_syscall_id, 0);
  return; 
}

void TCPAssignment::procACK(std::pair<u_int, u_int>my_addr, std::pair<u_int, u_int>their_addr, uint32_t seq_num, uint32_t ack_num, u_int window_size)
{
  // std::cout << "---------------------------------PROCACK " << seq_num << " " << ack_num << "\n";
  std::pair<u_int, u_int> fd_pid = {0, 0};

  if (their_addr_to_fd_pid.find({INADDR_ANY, their_addr.second}) != their_addr_to_fd_pid.end())
  {
    fd_pid = their_addr_to_fd_pid[{INADDR_ANY, their_addr.second}];
  }
  else
  {
    fd_pid = their_addr_to_fd_pid[their_addr];
  }

  SocketInfo &newSocketInfo = fd_pid_to_socket_info[fd_pid]; 


  if (newSocketInfo.state == TCP_FIN_WAIT1 && ack_num == newSocketInfo.next_ack_fin)
  {
    // std::cout<< "GOT TCP_FIN_WAIT1\n";
    newSocketInfo.state = TCP_FIN_WAIT2;
    return;
  }

  if (newSocketInfo.state == TCP_SYN_RECV)
  {
    newSocketInfo.state = TCP_ESTABLISHED;
    newSocketInfo.senderBuffer.acked_bytes = 1;
    if (my_addr_to_fd_pid.find({INADDR_ANY, my_addr.second}) != my_addr_to_fd_pid.end())
    {
      fd_pid = my_addr_to_fd_pid[{INADDR_ANY, my_addr.second}];
    }
    else
    {
      fd_pid = my_addr_to_fd_pid[my_addr];
    }

    // std::cout << "will try to find fd_pid at ACK " << fd_pid.first << " " << fd_pid.second << "\n";
    SocketInfo &socketInfo = fd_pid_to_socket_info[fd_pid]; 


    if (socketInfo.accept_blocked)
    {
      socketInfo.accept_blocked = false;
      std::pair<int, int> new_fd_pid = socketInfo.backlog_fd_pid.front();
      socketInfo.backlog_fd_pid.pop();
      // std::cout<< "+++++++++++++++++++++++++++RETURN ACCEPT OF PROCACK with SOCKFD for PID " << new_fd_pid.first << " " << new_fd_pid.second <<"\n";
      returnSystemCall(socketInfo.accept_syscall_id, new_fd_pid.first);
      return;
    }

    // std::cout << "backlog size before pop " << socketInfo.backlog_fd_pid.size() << "\n";
    std::pair<int, int> new_fd_pid = socketInfo.backlog_fd_pid.front();
    socketInfo.backlog_fd_pid.pop();

    socketInfo.q_fd_pid.push(new_fd_pid);
    return;
  }

  // TCP_ESTABLISHED communication

  if (newSocketInfo.ack_num_to_timer_id.find(ack_num) != newSocketInfo.ack_num_to_timer_id.end())
  {
    // found 
    // std::cout<<"CANCEL TIMER "<< newSocketInfo.ack_num_to_timer_id[ack_num] << "\n";
    cancelTimer(newSocketInfo.ack_num_to_timer_id[ack_num]);
  }
  else 
  {
    // TODO: do something when ack after procfinack comes
    std::cout<<"DIDN't find ack in ack_num_to_timer_id " << ack_num<< "\n";
    // throw std::exception();
    return;
  }

  int bytes_to_ack = ack_num - newSocketInfo.seq_num - newSocketInfo.senderBuffer.acked_bytes;
  // for (int i = 0; i < bytes_to_ack; i ++)
  // {
  //   newSocketInfo.senderBuffer.buf.pop_front();
  // }
  newSocketInfo.senderBuffer.acked_bytes += bytes_to_ack;
  newSocketInfo.senderBuffer.not_sent -= bytes_to_ack;
  newSocketInfo.senderBuffer.can_receive = window_size;

  // createAndSendWritePackets(newSocketInfo); TODO: currently this does nothing but something like this should be called after ack
}

void TCPAssignment::procFINACK(std::pair<u_int, u_int>my_addr, std::pair<u_int, u_int>their_addr, uint32_t seq_num, uint32_t ack_num)
{
  // std::cout << "---------------------------------PROCFINACK \n";
  std::pair<u_int, u_int> fd_pid = {0, 0};
  if (their_addr_to_fd_pid.find({INADDR_ANY, their_addr.second}) != their_addr_to_fd_pid.end())
  {
    fd_pid = their_addr_to_fd_pid[{INADDR_ANY, their_addr.second}];
  }
  else
  {
    fd_pid = their_addr_to_fd_pid[their_addr];
  }

  SocketInfo &socketInfo = fd_pid_to_socket_info[fd_pid];
  
  socketInfo.seq_num++;
  socketInfo.ack_num = seq_num + 1;

  if (socketInfo.state == TCP_FIN_WAIT2)
  {
    // std::cout<< "GOT TCP_FIN_WAIT2\n";
    Packet packet = createPacket(socketInfo,  TH_ACK);
    sendPacket("IPv4", std::move(packet));
    UUID timerID = addTimer(TimerCommand(DO_RETRANS, socketInfo, packet), TimeUtil::makeTime(RTT_TIME, TimeUtil::MSEC));
    int expect_ack_num = socketInfo.seq_num + socketInfo.senderBuffer.acked_bytes + socketInfo.senderBuffer.not_sent;
    socketInfo.ack_num_to_timer_id[expect_ack_num] = timerID;
    implicit_close(socketInfo.close_syscall_id, socketInfo.fd_pid);
    return;
  }

  Packet packet = createPacket(socketInfo,  TH_ACK);
  sendPacket("IPv4", std::move(packet));
  
  UUID timerID = addTimer(TimerCommand(DO_RETRANS, socketInfo, packet), TimeUtil::makeTime(RTT_TIME, TimeUtil::MSEC));
  int expect_ack_num = socketInfo.seq_num + socketInfo.senderBuffer.acked_bytes + socketInfo.senderBuffer.not_sent;
  socketInfo.ack_num_to_timer_id[expect_ack_num] = timerID;
  socketInfo.state = TCP_CLOSE_WAIT;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count)
{
  // std::cout << "--------------------syscall_read " << sockfd << " " << pid  << " " << count << "\n";

  SocketInfo &socketInfo = fd_pid_to_socket_info[{sockfd, pid}]; 

  if (socketInfo.receiverBuffer.buf.size() == 0)
  {
    // std::cout << "+++++++++++++++BLOCKED READ\n";
    socketInfo.receiverBuffer.uuid = syscallUUID;
    socketInfo.receiverBuffer.count = count;
    socketInfo.receiverBuffer.blocked = true;
    socketInfo.receiverBuffer.user_buf = buf;
    return;
  }

  int bytes_to_read = std::min((int) socketInfo.receiverBuffer.buf.size(), (int) count);
  for (int i = 0; i < bytes_to_read; i++)
  {
    memcpy(buf + i, &socketInfo.receiverBuffer.buf[0], 1);
    socketInfo.receiverBuffer.buf.pop_front();
  }

  socketInfo.receiverBuffer.window_size += bytes_to_read;
  returnSystemCall(syscallUUID, bytes_to_read);
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count)
{
  // std::cout << "--------------------syscall_write " << sockfd << " " << pid << " " << count <<  "\n";


  SocketInfo &socketInfo = fd_pid_to_socket_info[{sockfd, pid}];
  
  int written = writeBytes(socketInfo, buf, count);
  // std::cout <<"written = " << written << "\n";
  returnSystemCall(syscallUUID, written);
}

int TCPAssignment::writeBytes(SocketInfo &socketInfo, const void *buf, size_t count)
{
  uint8_t *p = (uint8_t *) buf;
  for (int i = 0; i < count; i++)
  {
    socketInfo.senderBuffer.buf.push_back(*p);
    p++;
  }
  
  // createAndSendWritePackets(socketInfo);
  sendWritePackets(socketInfo);
  return count;
}

void TCPAssignment::sendWritePackets(SocketInfo &socketInfo)
{
  int q_size = static_cast<int>(socketInfo.senderBuffer.buf.size());
  int bytes_to_send = std::min(q_size, socketInfo.senderBuffer.can_receive);

  while (bytes_to_send != 0)
  {
    int bytes = std::min(512, bytes_to_send); 
    Packet packet = createPacket(socketInfo, TH_ACK, bytes);
    sendPacket("IPv4", std::move(packet));
    bytes_to_send -= bytes;
    socketInfo.senderBuffer.not_sent += bytes; // makes seq_num correct

    UUID timerID = addTimer(TimerCommand(DO_RETRANS, socketInfo, packet), TimeUtil::makeTime(RTT_TIME, TimeUtil::MSEC));
    int expect_ack_num = socketInfo.seq_num + socketInfo.senderBuffer.acked_bytes + socketInfo.senderBuffer.not_sent;
    socketInfo.ack_num_to_timer_id[expect_ack_num] = timerID;
    // std:: cout<<"ADDED ACK_NUM " << expect_ack_num << "\n";
    for (int i = 0; i < bytes; i ++)
    {
      socketInfo.senderBuffer.buf.pop_front();
    }
  }

  socketInfo.senderBuffer.can_receive -= bytes_to_send; // TODO: IDK WHY
}

void TCPAssignment::createAndSendWritePackets(SocketInfo &socketInfo)
{
  int q_size = static_cast<int>(socketInfo.senderBuffer.buf.size());
  int bytes_to_send = std::min(q_size - socketInfo.senderBuffer.not_sent, socketInfo.senderBuffer.can_receive);

  while (bytes_to_send != 0)
  {
    int bytes = std::min(512, bytes_to_send); 
    Packet packet = createPacket(socketInfo, TH_ACK, bytes);
    sendPacket("IPv4", std::move(packet));
    bytes_to_send -= bytes;
    socketInfo.senderBuffer.not_sent += bytes; // makes seq_num correct
  }

  socketInfo.senderBuffer.can_receive -= bytes_to_send; // TODO: IDK WHY
}

void TCPAssignment::receiveBytes(Packet packet, std::pair<u_int, u_int> my_addr, std::pair<u_int, u_int> their_addr, uint32_t seq_num)
{
  std::pair<u_int, u_int> fd_pid = {0, 0};
  if (their_addr_to_fd_pid.find({INADDR_ANY, their_addr.second}) != their_addr_to_fd_pid.end())
  {
    fd_pid = their_addr_to_fd_pid[{INADDR_ANY, their_addr.second}];
  }
  else
  {
    fd_pid = their_addr_to_fd_pid[their_addr];
  }

  SocketInfo &socketInfo = fd_pid_to_socket_info[fd_pid];

  int count = packet.getSize() - 54;

  for (int i = 0; i < count; i++)
  {
    uint8_t p = 0;
    packet.readData(54 + i, &p, 1);
    socketInfo.receiverBuffer.buf.push_back(p);
  }

  int buffer_size = (int) socketInfo.receiverBuffer.buf.size();
  socketInfo.receiverBuffer.window_size = 51200 - buffer_size;
  socketInfo.ack_num = seq_num  + count;

  if (socketInfo.receiverBuffer.blocked)
  {
    int bytes_to_read = std::min((int) socketInfo.receiverBuffer.buf.size(), socketInfo.receiverBuffer.count);
    for (int i = 0; i < bytes_to_read; i++)
    {
      memcpy(socketInfo.receiverBuffer.user_buf + i, &socketInfo.receiverBuffer.buf[0], 1);
      socketInfo.receiverBuffer.buf.pop_front();
    }

    socketInfo.receiverBuffer.window_size += bytes_to_read;
    returnSystemCall(socketInfo.receiverBuffer.uuid, bytes_to_read);
    socketInfo.receiverBuffer.blocked = false;
    // TODO: do I have to unblock it ??
  }

  Packet newPacket = createPacket(socketInfo, TH_ACK);
  sendPacket("IPv4", std::move(newPacket));

}
} // namespace E
