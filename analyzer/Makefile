CC = gcc
CXX = g++
INCLUDES = -I./inlcude
CXXFLAGS = -fPIC -std=c++11
VPATH = so
LIBS = -L./so -L../so
SHAREDS = -lpcap -lsharpknifecommon -lmysqlcppconn8 -lmysqlcppconn -ldbconnect 
SODIR = ./so/
THIRD_PARTY_SHAREDS = -lpcap -lmysqlcppconn8 -lmysqlcppconn
THIRD_PARTY_SODIR = ./third_party/

OBJS = \
		analyzer_manager.o \
		analyzer.o \
		protocol/eth/eth.o \
		protocol/ipv4/ipv4.o 

HEADER = \
		analyzer_manager.h \
		analyzer.h \
		protocol/eth/eth.h \
		protocol/ipv4/ipv4.h 


Main : makedir $(OBJS) package

makedir:
	-@mkdir -p so

$(OBJS): $(HEADER)
	@g++ -c $*.cpp $(CXXFLAGS) -o $(SODIR)$(notdir $*).o
	@echo $*.o

package: makedir
	g++ ./so/*.o $(CXXFLAGS) -shared -o $(SODIR)libanalyzer.so
	cp $(SODIR)libanalyzer.so ../so/

clean :
	-rm -rf ./so/*.o ./so/*.so

