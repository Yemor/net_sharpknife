CC = gcc
CXX = g++
INCLUDES = -I./inlcude
CXXFLAGS = -fPIC -std=c++11
RPATH = -Wl,-rpath=./so -Wl,-rpath=./third_party 
VPATH = so
LIBS = -L./so -L./third_party
SHAREDS = -lsharpknifecommon  -lanalyzer -lcapturer -ldbconnect
SODIR = ./so/
THIRD_PARTY_SHAREDS = -lpcap -lmysqlcppconn8 -lmysqlcppconn
THIRD_PARTY_SODIR = ./third_party/
DIRS = capturer

OBJS = \
		sharpknife_common.o\
		json11.o 

HEADER = \
		sharpknife_common.h\
		json11.hpp 

Main : makedir $(OBJS) package libanalyzer.so libdbconnect.so libcapturer.so
		g++ main.cpp $(SODIR)*.so $(THIRD_PARTY_SODIR)*.so $(CXXFLAGS) $(RPATH) -o main $(LIBS) $(THIRD_PARTY_SHAREDS) $(SHAREDS)

libcapturer.so : libdbconnect.so
	@echo "make capturer"
	@make -C capturer

libdbconnect.so :
	@echo "make dbconnect"
	@make -C dbconnect

libanalyzer.so :
	@echo "make analyzer"
	@make -C analyzer

makedir:
	-@mkdir -p so
	-@chmod -R 777 so

$(OBJS): $(HEADER)
	@g++ -c $*.cpp $(CXXFLAGS) -o $(SODIR)$(notdir $*).o
	@echo $*.o

package: makedir
	@g++ ./so/*.o $(CXXFLAGS) -shared -o $(SODIR)libsharpknifecommon.so

clean :
	-rm -rf main ./so/*.o
	-rm -rf ./so/*.so
	@make -C capturer clean
	@make -C dbconnect clean
	@make -C analyzer clean

test :
	make && ./main
