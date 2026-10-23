CC=gcc
# CURATED (reverie): e9tool only decodes and formats instructions, so this
# vendored copy is built with the upstream-supported ZYDIS_DISABLE_ENCODER
# switch and ships without the encoder sources. src/Encoder.c,
# src/EncoderData.c, include/Zydis/Encoder.h,
# include/Zydis/Internal/EncoderData.h, and the 2.6 MB generated
# src/Generated/EncoderTables.inc were never in OBJS below and are removed.
# Anything that includes <Zydis/Zydis.h> against this tree must define the same
# macro; see the e9patch Makefile's E9TOOL_CXXFLAGS.
CFLAGS=-fPIC -Os -DZYDIS_DISABLE_ENCODER -I include/ \
       -I dependencies/zycore/include/ -I src/

OBJS=src/Decoder.o \
     src/DecoderData.o \
     src/FormatterATT.o \
     src/FormatterBase.o \
     src/FormatterBuffer.o \
     src/Formatter.o \
     src/FormatterIntel.o \
     src/MetaInfo.o \
     src/Mnemonic.o \
     src/Register.o \
     src/SharedData.o \
     src/String.o \
     src/Utils.o \
     src/Zydis.o \
     dependencies/zycore/src/Allocator.o \
     dependencies/zycore/src/ArgParse.o \
     dependencies/zycore/src/Bitset.o \
     dependencies/zycore/src/Format.o \
     dependencies/zycore/src/List.o \
     dependencies/zycore/src/String.o \
     dependencies/zycore/src/Vector.o \
     dependencies/zycore/src/Zycore.o

all: $(OBJS)
	ar rcs libZydis.a $(OBJS)

clean:
	rm -rf libZydis.a $(OBJS)

