# RUN FOLLOWING COMMAND.
# bare -- make

TARGET   = pcap
SRCDIR   = ./src/
SRCS     = $(shell find $(SRCDIR) -name "*.c" -type f | xargs)
OBJDIR   = ./obj/
OBJS     = $(addprefix $(OBJDIR), $(notdir $(SRCS:.c=.o)))
INCDIR   = include
CC       = gcc
CFLAGS   = -g -Wall

# make target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# make objects
${OBJDIR}%.o: ${SRCDIR}%.c
	$(CC) $(CFLAGS) -I $(INCDIR) -o $@ -c $<

# make target & run
.PHONY: run
run: $(TARGET)
	sudo ./$(TARGET)

.PHONY: clean
clean:
	rm -f $(OBJS)

ctags: $(SRCDIR)
	ctags -R $(SRCDIR)
