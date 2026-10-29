# SPDX-License-Identifier: MIT OR Apache-2.0
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
CFLAGS += -Iinclude
LDLIBS = -lpthread -lm
OBJS = src/main.o src/stats.o

c-demo: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

src/%.o: src/%.c include/stats.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f c-demo $(OBJS)

.PHONY: clean
