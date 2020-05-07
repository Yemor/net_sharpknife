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
		net_interface.o \
		capture_api.o \
		capturer.o

HEADER = \
		capture_api.h \
		capturer.h \
		net_interface.h


Main : makedir $(OBJS) package

makedir:
	-@mkdir -p so

$(OBJS): $(HEADER)
	@g++ -c $*.cpp $(CXXFLAGS) -o $(SODIR)$(notdir $*).o
	@echo $*.o

package: makedir
	g++ ./so/*.o $(CXXFLAGS) -shared -o $(SODIR)libcapturer.so
	cp $(SODIR)libcapturer.so ../so/

clean :
	-rm -rf ./so/*.o ./so/*.so

