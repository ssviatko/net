INCL = -I../../ss2x/libss2x
BUILD_NUMBER_FILE = build.no
RELEASE_NUMBER_FILE = release.no
BUILD_DATE=$$(date +'%Y-%m-%d %H:%M %z %Z')
BUILD_NUMBER=$$(cat $(BUILD_NUMBER_FILE))
RELEASE_NUMBER=$$(cat $(RELEASE_NUMBER_FILE))
CFLAGS = -DBUILD_NUMBER="\"$(BUILD_NUMBER)\"" -DBUILD_DATE="\"$(BUILD_DATE)\"" -DRELEASE_NUMBER="\"$(RELEASE_NUMBER)\"" -std=c++23 -Wall -O3 $(INCL)
UNAME = $(shell uname)
CC = gcc
CPP = g++
LD = g++
LDFLAGS = -Wl,-rpath,../../ss2x/libss2x -L../../ss2x/libss2x -lpthread -lncurses -lss2x -lstdc++exp

AUTH_OBJS = auth.o auth_test.o
AUTH_TARGET = auth_test
PWGEN_OBJS = auth.o pwgen.o
PWGEN_TARGET = pwgen
LOGONGEN_OBJS = logongen.o
LOGONGEN_TARGET = logongen
CRGEN_OBJS = auth.o crgen.o
CRGEN_TARGET = crgen
SVR_TEST_OBJS = auth.o esr.o server_base.o command_server.o fortune_server.o svr_test.o
SVR_TEST_TARGET = svr_test

all: $(AUTH_TARGET) $(PWGEN_TARGET) $(LOGONGEN_TARGET) $(CRGEN_TARGET) $(SVR_TEST_TARGET)

$(AUTH_TARGET): $(AUTH_OBJS)

	@if ! test -f $(BUILD_NUMBER_FILE); then echo 0 > $(BUILD_NUMBER_FILE); fi
	@echo $$(($$(cat $(BUILD_NUMBER_FILE)) + 1)) > $(BUILD_NUMBER_FILE)
	$(LD) $(AUTH_OBJS) -o $(AUTH_TARGET) $(LDFLAGS)

$(PWGEN_TARGET): $(PWGEN_OBJS)

	$(LD) $(PWGEN_OBJS) -o $(PWGEN_TARGET) $(LDFLAGS)
	
$(LOGONGEN_TARGET): $(LOGONGEN_OBJS)

	$(LD) $(LOGONGEN_OBJS) -o $(LOGONGEN_TARGET) $(LDFLAGS)
	
$(CRGEN_TARGET): $(CRGEN_OBJS)

	$(LD) $(CRGEN_OBJS) -o $(CRGEN_TARGET) $(LDFLAGS)
	
$(SVR_TEST_TARGET): $(SVR_TEST_OBJS)

	$(LD) $(SVR_TEST_OBJS) -o $(SVR_TEST_TARGET) $(LDFLAGS)
	
%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.o: %.cc
	$(CPP) $(CFLAGS) -c $<

clean:
	rm -f *.o
	rm -f *~
	rm -f $(AUTH_TARGET)
	rm -f $(PWGEN_TARGET)
	rm -f $(CRGEN_TARGET)
	rm -f $(LOGONGEN_TARGET)
	rm -f $(SVR_TEST_TARGET)
	
	
	
