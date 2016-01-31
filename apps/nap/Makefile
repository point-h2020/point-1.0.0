ifeq ($(OPT), O1)
	OPT=O1
else ifeq ($(OPT), O3)
	OPT=O3
else
	OPT=O2
endif

CXXFLAGS = -std=c++11 -$(OPT) -g -Wall -fno-strict-aliasing -fmessage-length=0

OBJS =	listeners/arplistener.o \
	handlers/httphandler.o \
	handlers/icnhandler.o \
	handlers/iphandler.o \
	buffercleaner.o\
	database.o \
	demux.o \
	helper.o \
	main.o \
	socket.o \
	transport.o \
	trace.o

LIBS = -lboost_program_options -lboost_system -lboost_thread -llog4cxx -lblackadder -lpcap -lconfig++ -lnet -L /lib64

TARGET = nap

$(TARGET):	$(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LIBS)

all: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
