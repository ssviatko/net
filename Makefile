INCL = -I./libss2x
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
LDFLAGS = -Wl,-rpath,./libss2x -Wl,-rpath=/usr/local/lib64 -L./libss2x -lpthread -lncurses -lss2x -lstdc++exp

CLI_OBJS = cli.o
CLI_TARGET = cli

all: $(CLI_TARGET)

$(CLI_TARGET): $(CLI_OBJS)

	@if ! test -f $(BUILD_NUMBER_FILE); then echo 0 > $(BUILD_NUMBER_FILE); fi
	@echo $$(($$(cat $(BUILD_NUMBER_FILE)) + 1)) > $(BUILD_NUMBER_FILE)
	$(LD) $(CLI_OBJS) -o $(CLI_TARGET) $(LDFLAGS)
	
%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.o: %.cc
	$(CPP) $(CFLAGS) -c $<

clean:
	rm -f *.o
	rm -f *~
	rm -f $(CLI_TARGET)
	
	
