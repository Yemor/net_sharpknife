CC = gcc
CXX = g++
INCLUDES = -I./inlcude
CXXFLAGS = -fPIC -std=c++11
VPATH = so
LIBS = -L./so -L../so -L../third_party
SHAREDS = -lsharpknifecommon 
SHAREDFILES = ../so/libsharpknifecommon.so 
SODIR = ./so/
THIRD_PARTY_SHAREDS = -lpcap -lmysqlcppconn8 -lmysqlcppconn
THIRD_PARTY_SODIR = ../third_party/

OBJS = \
		dbconnect_api.o 

HEADER = \
		dbconnect_api.h 


Main : makedir $(OBJS) package

makedir:
	-@mkdir -p so

$(OBJS): $(HEADER)
	@g++ -c $*.cpp $(CXXFLAGS) -o $(SODIR)$*.o
	@echo $*.o

package: makedir
	g++ ./so/*.o $(CXXFLAGS) -shared -o $(SODIR)libdbconnect.so
	cp $(SODIR)libdbconnect.so ../so/

clean :
	-rm -rf ./so/*.o ./so/*.so

