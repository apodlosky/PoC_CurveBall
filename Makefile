#
# CVE-2020-0601 - CurveBall PoC
# Adam Podlosky <apodlosky@gmail.com>
#

TARGET_1	= curveball
TARGETS		= $(TARGET_1)

OBJECTS_1	= curveball.o
OBJECTS		= $(OBJECTS_1)

CC	= gcc
CFLAGS	= -Wall -std=gnu99
LIBS	= -lcrypto -lssl

DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS+= -g3 -DDEBUG
else
	CFLAGS+= -O2 -DNDEBUG
endif

.PHONY: default all clean

all: $(TARGETS)

default: all

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET_1): $(OBJECTS_1)
	$(CC) $(CFLAGS) $(OBJECTS_1) $(LIBS) -o $@

clean:
	-rm -f $(OBJECTS)
	-rm -f $(TARGETS)
