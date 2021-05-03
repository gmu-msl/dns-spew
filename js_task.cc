#include <stdio.h>

#include <vantages/dns_packet.h>
#include <vantages/dns_rr.h>
#include <vantages/dns_name.h>

#include "js_task.h"
#include "js_defs.h"

JackSniffTask::JackSniffTask(const char *p_szQuery, in_addr_t p_tIP)
  : // m_tIP(p_tIP),
    m_sName(p_szQuery)
{
  setNameserver(p_tIP);
  DnsPacket *pPkt = new DnsPacket(true);
  DnsName oName(m_sName);
  DnsRR *pQ = DnsRR::question(oName, DNS_RR_A);
  pQ->set_class(DNS_CLASS_IN);
  pPkt->addQuestion(*pQ);
  setQuery(pPkt);
}

JackSniffTask::~JackSniffTask()
{

}

