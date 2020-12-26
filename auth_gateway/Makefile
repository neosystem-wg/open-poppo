PROGRAM = auth_gateway
SRCS    = \
	main.cpp \
	application.cpp \
	http_request_header.cpp \
	http_response_header.cpp \
	common.cpp \
	http_common.cpp \
	config.cpp \
	log.cpp \
	session.cpp \
	session_manager.cpp \
	oauth1.cpp \
	auth.cpp \
	json_reader.cpp \
	json_writer.cpp \
	http2_huffman.cpp \
	http2_static_headers_table.cpp \
	http2_util.cpp
ifndef CFLAGS
	CFLAGS = -I../cpp-bredis/include -std=c++2a -O0 -g -pg -W -Wall -Wcast-align -Wcast-qual -Wcomment -Wconversion -Wformat -Wlong-long -Wno-import -Wparentheses -Wpointer-arith -Wreturn-type -Wshadow -Wswitch -Wtrigraphs -Wunused -Wwrite-strings
endif
ifndef LDFLAGS
	LDFLAGS = -pg -lboost_program_options -lboost_system -lpthread -lssl -lcrypto
endif
INCLUDES   = $(SRCS:.cpp=.hpp)
OBJS       = $(SRCS:.cpp=.o)
CC         = g++
MAKEFILE   = Makefile
RM         = rm
RMFLAGS	   = -f
TOUCH      = touch
DEPS       = .deps

.PHONY: all clean dep

all: dep $(PROGRAM)

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(PROGRAM) $(DEPS) $(PROGRAM).log core core.[0-9]* gmon.out

dep: $(OBJS:.o=.cpp)
	-@ $(TOUCH) $(DEPS)
	-@ $(RM) $(DEPS)
	-@ for i in $^; do \
		cpp -std=c++2a -MM $$i | sed "s/\ [_a-zA-Z0-9][_a-zA-Z0-9]*\.cpp//g" >> $(DEPS); \
	done

$(PROGRAM): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

check-syntax:
	$(CC) -o nul $(CFLAGS) $(INCLUDES) -S ${CHK_SOURCES}

-include $(DEPS)

html:
	gtags -v
	htags -ansx

pch:
	clang++ -cc1 -fcxx-exceptions -x c++-header *.hpp -emit-pch -o .pch
