CC = gcc
CXX = g++
INCLUDES = -I./inlcude
CXXFLAGS = -fPIC
VPATH = so
LIBS = -L./so
SHAREDS = -lcapturer -lpcap -lsharpknifecommon 
SODIR = ./so/
DIRS = capturer

OBJS = \
		sharpknife_common.o

HEADER = \
		sharpknife_common.h

Main : makedir $(OBJS) package libcapturer.so 
		g++ main.cpp $(SODIR)*.so $(CXXFLAGS) -o main

libcapturer.so :
	@echo "make capturer"
	@make -C capturer

makedir:
	-@mkdir -p so

$(OBJS): $(HEADER)
	@g++ -c $*.cpp $(CXXFLAGS) -o $(SODIR)$*.o
	@echo $*.o

package: makedir
	g++ ./so/*.o $(CXXFLAGS) -shared -o $(SODIR)libsharpknifecommon.so

clean :
	-rm -rf main ./so/*.o
	-rm -rf ./so/libsharpknifecommon.so ./so/libcapturer.so
	make -C capturer clean

test :
	make && ./main
