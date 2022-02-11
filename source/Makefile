CC       = gcc
CC2      = gcc
DLLWRAP  = dllwrap
CFLAGS   = -Os -mthreads -fno-exceptions
#-s -O3
LDFLAGS  = -mthreads -fno-exceptions
INCLUDES = 
LIBS     = -lgdi32 -s
#--image-base=0x10000000 #image-baseを操作することによりexedit.aufの再配置を起こしてデバッグ。
TARGET   = ./eclipse_fast.auf
OBJ		 = main.o
DEF      = eclipse_fast.def
SRC		 = $(OBJ:%.o=./%.c)
LINKOBJ	 = $(OBJ:%.o=obj/%.o) obj/asm.o

all : $(TARGET)

$(TARGET): $(LINKOBJ)
	$(DLLWRAP) -k -def $(DEF) --driver-name $(CC2) $(LDFLAGS) -o $(TARGET) $(LINKOBJ) $(LIBS)

obj/%.o : ./%.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES)

obj/%.o : ./%.S
	$(CC) -c $< -o $@ -masm=intel $(CFLAGS) $(INCLUDES)
