CC = gcc
CXX = g++
INCLUDES = -I./inlcude
CXXFLAGS = -fPIC -std=c++11
VPATH = so
LIBS = -L./so
SHAREDS = -lcapturer -lpcap -lsharpknifecommon -ldbconnect
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

Main : makedir $(OBJS) package libdbconnect.so libcapturer.so 
		g++ main.cpp $(SODIR)*.so $(THIRD_PARTY_SODIR)*.so $(CXXFLAGS) -o main

libcapturer.so : libdbconnect.so
	@echo "make capturer"
	@make -C capturer

libdbconnect.so :
	@echo "make dbconnect"
	@make -C dbconnect

makedir:
	-@mkdir -p so
	-@chmod -R 777 so

$(OBJS): $(HEADER)
	@g++ -c $*.cpp $(CXXFLAGS) -o $(SODIR)$*.o
	@echo $*.o

package: makedir
	@g++ ./so/*.o $(CXXFLAGS) -shared -o $(SODIR)libsharpknifecommon.so

clean :
	-rm -rf main ./so/*.o
	-rm -rf ./so/*.so
	@make -C capturer clean
	@make -C dbconnect clean

test :
	make && ./main
