CC = gcc
CXX = g++
INCLUDES = -I./inlcude
CXXFLAGS = -fPIC
VPATH = so
LIBS = -L./so -L../so
SHAREDS = -lpcap -lsharpknifecommon
SHAREDFILES = ../so/libpcap.so ../so/libsharpknifecommon.so
SODIR = ./so/

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
	@g++ -c $*.cpp $(CXXFLAGS) -o $(SODIR)$*.o
	@echo $*.o

package: makedir
	g++ ./so/*.o $(CXXFLAGS) -shared -o $(SODIR)libcapturer.so
	cp $(SODIR)libcapturer.so ../so/

clean :
	-rm -rf ./so/*.o ./so/*.so

