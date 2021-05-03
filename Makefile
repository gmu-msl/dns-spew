CC =    gcc
CXX =    g++
DEFINES = -g -Wall -Werror -DHAVE_CONFIG_H
CFLAGS =  -g -O2 -D_DNS_NO_SHA256  $(DEFINES)
CXXFLAGS =  -g -O2 -D_DNS_NO_SHA256 
CPPFLAGS = -DDEBUG -D_POSIX_THREADS -D_REENTRANT -I/usr/local/include -I/opt/local/include 
LDFLAGS = -L/usr/local/lib -L/opt/local/lib  -L/opt/local/lib 
LIBS = -lvdns -lpcap -lpthread -lc

prefix = /usr/local
exec_prefix = ${prefix}
libdir = ${exec_prefix}/lib

OBJS = js_mutex.o js_mutex_hdlr.o js_task.o

PROG = dns-spew

.cc.o:
	$(CXX) $(CXXFLAGS) $(DEFINES) $(CPPFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) $(DEFINES) $(CPPFLAGS) -c $<

all: $(PROG)

$(PROG): $(OBJS) $(DSYNC_OBJS)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(CPPFLAGS) $(LDFLAGS) -o $@ $@.cc $(OBJS) $(LIBS)

clean:
	rm -f $(PROG) $(OBJS) 
