#Makefil
CC = gcc
#CFLAGS = -W -Wmak
TARGET = pcap-test
OBJECTS = pcap-test.c

all : $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ -lpcap

clean:
	rm -f *.o
	rm -f $(TARGET)
