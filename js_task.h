#ifndef _JS_TASK_H
#define _JS_TASK_H

#include <netinet/in.h>

#include <vantages/dns_task.h>

class JackSniffTask : public DnsTask
{
  // Member Variables
  private:
    // in_addr_t m_tIP;
    std::string m_sName;

  // Methods
  public:
    JackSniffTask(const char *p_szQuery, in_addr_t p_tIP);
    virtual ~JackSniffTask();
};

#endif
