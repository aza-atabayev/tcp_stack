/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

namespace E {

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;
  virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
  virtual void syscall_close(UUID syscallUUID, int pid, int sockfd);
  virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, sockaddr* addr, socklen_t addrlen);
  virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, sockaddr* addr, socklen_t* addrlen);
  virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, sockaddr * addr, socklen_t* addrlen);
  virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog_len);
  virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd, sockaddr * addr, socklen_t* addrlen);
  virtual void syscall_connect(UUID syscallUUID, int pid, int sockfd, sockaddr* addr, socklen_t addrlen);

  
  struct PacketInfo 
  {
    std::pair<u_int, u_int>src_addr;
    std::pair<u_int, u_int>dst_addr;
    uint32_t seq_num;
    uint32_t ack_num;

    PacketInfo(){}
    PacketInfo(std::pair<u_int, u_int>src_addr, 
    std::pair<u_int, u_int>dst_addr, uint32_t seq_num, 
    uint32_t ack_num): src_addr(src_addr), dst_addr(dst_addr), seq_num(seq_num), ack_num(ack_num){}
  };

  struct SocketInfo 
  {
    std::pair<int, int> fd_pid;
    std::pair<u_int, u_int>src_addr;
    std::pair<u_int, u_int>dst_addr;
    u_int state;

    std::queue<PacketInfo>q_packets;
    int backlog = 0;
    // int parent_fd;
    // std::queue<int>child_fds;

    UUID connect_syscall_id;
    UUID accept_syscall_id;
    bool accept_blocked = false;

    uint32_t seq_num;
    uint32_t ack_num;

    SocketInfo(): accept_blocked(false){}
    SocketInfo(std::pair<int, int> fd_pid, u_int state): fd_pid(fd_pid), state(state),  accept_blocked(false){}
  };

  virtual void readPacket(Packet packet, std::pair<u_int, u_int>&src_addr, std::pair<u_int, u_int>&dst_addr, uint32_t &seq_num, uint32_t &ack_num, u_int &flags);
  virtual Packet createPacket(SocketInfo &socketInfo, u_int flags);

  Packet last_packet = Packet(54);

  virtual void procSYN(std::pair<u_int, u_int>src_addr, std::pair<u_int, u_int>dst_addr, uint32_t seq_num, uint32_t ack_num);
  virtual void procSYNACK(std::pair<u_int, u_int>src_addr, std::pair<u_int, u_int>dst_addr, uint32_t seq_num, uint32_t ack_num);
  virtual void procACK(std::pair<u_int, u_int>src_addr, std::pair<u_int, u_int>dst_addr, uint32_t seq_num, uint32_t ack_num);

  virtual void toHost(std::pair<u_int, u_int>&addr)
  {
    addr = {ntohl(addr.first), ntohs(addr.second)};
  }

  virtual void toNetwork(std::pair<u_int, u_int>&addr)
  {
    addr = {htonl(addr.first), htons(addr.second)};
  }



  std::map<std::pair<u_int, u_int>, std::pair<int, int>>addr_to_fd_pid;
  std::map<std::pair<int, int>, std::pair<u_int, u_int>>fd_pid_to_addr;
  std::map<std::pair<int, int>, SocketInfo>fd_pid_to_socket_info;



  
public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
