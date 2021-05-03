#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

/*
#include <vantages/dns_resolver.h>
#include <vantages/dns_task.h>
#include <vantages/dns_err.h>
*/
#include <vantages/dns.h>

#include "js_task.h"
#include "js_defs.h"

using namespace std;

void _usage()
{
  fprintf(stdout, "dns-spew -r <resolver> -q <file of DNS names to query> [ -c <concurrency> ] [ -o <output file> ] | -h\n");
}

void _print_task(DnsTask *p_pTask, FILE *p_pOutFile)
{
  if (NULL == p_pTask) {
    js_log("NULL task.\n");
  }
  else if (NULL == p_pOutFile) {
    js_log("Out file is NULL.\n");
  }
  else {
    RRList_t tRRset;
    DnsPacket *pResp = p_pTask->getResponse();
    if (NULL == pResp) {
      js_log("Got NULL response.\n");

    }
    else if (!pResp->getAnswers(tRRset)) {
      js_log("Got no answer(s).\n");
    }
    else {
      for (RRIter_t tIter = tRRset.begin();
           tRRset.end() != tIter;
           tIter++) {
        DnsRR *pRR = *tIter;
        if (DNS_RR_A == pRR->type()) {
          fprintf(p_pOutFile, "%s %s\n", pRR->getName().c_str(), ((DnsA *) pRR)->toString().c_str());
        }
      }
    }
  }
}

void _chomp(char *p_szLine, int p_iMaxLen)
{ 
  // If we have a line...
  if (NULL != p_szLine)
  { 
    int i = 0;
    // Find the length.
    for (i = 0; '\0' != p_szLine[i] && i < p_iMaxLen; i++) {}
    //
    // If i makes sense...
    if (i < p_iMaxLen)
    { 
      // Go from the end to the beginning turning \r and \n into \0 until
      // we see the first non-\r\n char.
      while (--i >= 0 && ('\n' == p_szLine[i] || '\r' == p_szLine[i]))
      { 
        p_szLine[i] = '\0';
      }
    }
  }
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  char *szResIP = NULL;
  int iErr = 0;
  struct in_addr tAddr;
  memset(&tAddr, 0, sizeof(tAddr));

  int iConcurrency = 20;
  char *szOutFile = NULL;
  char *szQueryFile = NULL;
  FILE *pQueryFile = NULL;;

  int c = 0;
  while ((c = getopt(argc, argv, "r:c:o:q:h")) != -1)
  {
    switch(c)
    {
      case 'r':
        szResIP = optarg;
        iErr = inet_pton(AF_INET, szResIP, &tAddr);
        if (0 == iErr) {
          js_log("Unable to convert resolver IP '%s' to IP address: %s\n", szResIP, strerror(errno));
        }
        break;
      case 'c':
        iConcurrency = (int) strtol(optarg, NULL, 10);
        break;
      case 'o':
        szOutFile = optarg;
        break;
      case 'q':
        szQueryFile = optarg;
        break;
      case 'h':
        _usage();
        exit(0);
        break;
      default:
        _usage();
        exit(1);
        break;
    }
  }

  if (NULL == szResIP)
  {
    js_log("Must specify resolver IP to use.\n");
    _usage();
  }
  else if (0 == iConcurrency)
  {
    js_log("Must specify valid Concurrency.\n");
    _usage();
  }
  else if (NULL == szQueryFile)
  {
    js_log("Must specify query.\n");
    _usage();
  }
  else if (NULL == (pQueryFile = fopen(szQueryFile, "r")))
  {
    js_log("Unable to open query file '%s': %s\n", szQueryFile, strerror(errno));
    _usage();
  }
  else
  {
    FILE *pOutFile = stdout;
    if (NULL != szOutFile)
    {
      if (NULL == (pOutFile = fopen(szOutFile, "w")))
      {
        js_log("Unable to open output file '%s' for writing.\n", szOutFile);
      }
    }

    if (NULL != pOutFile)
    {
      DnsResolver oRes;
      oRes.setConcurrency(iConcurrency);
      oRes.setRetries(2);

      while (!feof(pQueryFile))
      {
        // time_t tLastCheck = 0;

        DnsTask *pTmpTask = NULL;
        for (int i = 0;
             i < iConcurrency
             && oRes.hasTasks()
             && NULL != (pTmpTask = oRes.recv());
             i++)
        {
          /*
          RRList_t tRRset;
          DnsPacket *pResp = pTmpTask->getResponse();
          if (NULL == pResp) {
            js_log("Got NULL response.\n");

          }
          else if (!pResp->getAnswers(tRRset)) {
            js_log("Got no answer(s).\n");
          }
          else {
            for (RRIter_t tIter = tRRset.begin();
                 tRRset.end() != tIter;
                 tIter++) {
              DnsRR *pRR = *tIter;
              if (DNS_RR_A == pRR->type()) {
                fprintf(pOutFile, "%s %s\n", pRR->getName().c_str(), ((DnsA *) pRR)->toString().c_str());
              }
            }
          }
          */
          _print_task(pTmpTask, pOutFile);
          delete pTmpTask;
        }

        if (!oRes.hasRoomToSend())
        {
          usleep(200);
        }
        else
        {
          char szFQDN[256];
          memset(szFQDN, 0, 256);
          for (int j = 0;
               j < iConcurrency
               && oRes.hasRoomToSend()
               && NULL != (fgets(szFQDN, 255, pQueryFile));
               j++)
          {
            _chomp(szFQDN, 255);

            JackSniffTask *pTask = new JackSniffTask(szFQDN, ntohl(tAddr.s_addr));
            // struct timeval tNow;
            // memset(&tNow, 0, sizeof(tNow));
            // gettimeofday(&tNow, NULL);
            // string sKey = DnsResolver::makeKey(*(pTask->getQuery()), ntohl(t));
            if (!oRes.send(pTask))
            {
              js_log("Unable to send task: %s\n", DnsError::getInstance().getError().c_str());
              delete pTask;
            }

            /*
            if (tNow.tv_sec > (tLastCheck + 300))
            {
              tLastCheck = tNow.tv_sec;
            }
            */

            memset(szFQDN, 0, 256);
          }
        }

        while (oRes.hasTasks()) {
          if (NULL == (pTmpTask = oRes.recv())) {
            usleep(500);
          }
          else {
            _print_task(pTmpTask, pOutFile);
            delete pTmpTask;
          }
        }

        iRet = 0;
      }
    }
  }

  return iRet;
}
