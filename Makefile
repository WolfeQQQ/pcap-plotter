CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap -lgd -lhpdf -lm

TARGET = pcap_analyzer
SRCS = main.c reader.c analyzer.c charts.c pdf.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) tcp_udp.png top_ports.png raport.pdf