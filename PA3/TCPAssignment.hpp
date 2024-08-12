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


#define RTT_TIME 100
#define DO_NOTHING 0
#define DO_RETRANS 1
#define DO_CLOSE 2

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
  virtual void syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count);
  virtual void syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count);

  struct ReceiverBuffer
  {
    int window_size;
    std::deque <uint8_t> buf;
    UUID uuid;
    int count;
    bool blocked;
    void *user_buf;

    ReceiverBuffer() : window_size(51200), blocked(false) {}
  };

  struct SenderBuffer
  {
    std::deque <uint8_t> buf;
    int acked_bytes;
    int not_sent;
    int can_receive;

    SenderBuffer() : acked_bytes(0), can_receive(51200), not_sent(0) {}
  };

  struct SocketInfo 
  {
    std::map<int, UUID>ack_num_to_timer_id;
    UUID syn_timer_id;
    UUID synack_timer_id;
    UUID ack_timer_id;

    int last_seq = -1;

    std::pair<int, int> fd_pid;
    std::pair<u_int, u_int>my_addr;
    std::pair<u_int, u_int>their_addr;
    u_int state;

    int RTT = 100;
    int devRTT = 0;

    ReceiverBuffer receiverBuffer;
    SenderBuffer senderBuffer;

    std::queue<std::pair<int, int>>backlog_fd_pid;
    std::queue<std::pair<int, int>>q_fd_pid;
    int backlog = 0;

    UUID connect_syscall_id;
    UUID accept_syscall_id;
    UUID close_syscall_id;
    uint32_t next_ack_fin = 0;

    uint32_t next_ack = 0;
    uint32_t next_seq = 0;

    bool accept_blocked = false;

    uint32_t seq_num = 0;
    uint32_t ack_num = 0;

    SocketInfo(): accept_blocked(false){}
    SocketInfo(std::pair<int, int> fd_pid, u_int state): fd_pid(fd_pid), state(state),  accept_blocked(false){}
  };


  struct TimerCommand
  {
    int command = DO_NOTHING;
    Packet packet = Packet(0);
    SocketInfo socketInfo = SocketInfo();

    TimerCommand(int command, SocketInfo &socketInfo): command(command), socketInfo(socketInfo) {}
    TimerCommand(int command, SocketInfo &socketInfo, Packet packet): command(command), socketInfo(socketInfo), packet(packet) {}
  };

  virtual bool readPacket(Packet packet, std::pair<u_int, u_int>&my_addr, std::pair<u_int, u_int>&their_addr, uint32_t &seq_num, uint32_t &ack_num, u_int &flags, u_int &window_size);
  virtual Packet createPacket(SocketInfo &socketInfo, u_int flags, int bytes = 0);

  Packet last_packet = Packet(54);

  virtual void procSYN(std::pair<u_int, u_int>my_addr, std::pair<u_int, u_int>their_addr, uint32_t seq_num, uint32_t ack_num);
  virtual void procSYNACK(std::pair<u_int, u_int>my_addr, std::pair<u_int, u_int>their_addr, uint32_t seq_num, uint32_t ack_num);
  virtual void procACK(std::pair<u_int, u_int>my_addr, std::pair<u_int, u_int>their_addr, uint32_t seq_num, uint32_t ack_num, u_int window_size);
  virtual void procFINACK(std::pair<u_int, u_int>my_addr, std::pair<u_int, u_int>their_addr, uint32_t seq_num, uint32_t ack_num);

  virtual void toHost(std::pair<u_int, u_int>&addr)
  {
    addr = {ntohl(addr.first), ntohs(addr.second)};
  }

  virtual void toNetwork(std::pair<u_int, u_int>&addr)
  {
    addr = {htonl(addr.first), htons(addr.second)};
  }

  virtual void sendWritePackets(SocketInfo &socketInfo);


  virtual int writeBytes(SocketInfo &socketInfo, const void *buf, size_t count);
  virtual void createAndSendWritePackets(SocketInfo &socketInfo);
  virtual void receiveBytes(Packet packet, std::pair<u_int, u_int> my_addr, std::pair<u_int, u_int> their_addr, uint32_t seq_num);
  virtual void implicit_close(UUID syscallUUID, std::pair<int, int> fd_pid);


  std::map<std::pair<u_int, u_int>, std::pair<int, int>>my_addr_to_fd_pid;
  std::map<std::pair<u_int, u_int>, std::pair<int, int>>their_addr_to_fd_pid;

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
