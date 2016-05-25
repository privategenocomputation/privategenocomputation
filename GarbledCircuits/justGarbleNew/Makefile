# ***********************************************
#                    JustGarble
# ***********************************************

SRCDIR   = src
OBJDIR   = obj
BINDIR   = bin
TESTDIR   = test
OBJECTFULL = obj/*.o

SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(SRCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

IDIR =../include
CC=gcc 
CFLAGS= -O3 -lm -lrt -lpthread -maes -msse4 -lmsgpackc -march=native -I$(IDIR)


AES = AESFullTest
LARGE = LargeCircuitTest
FILE = CircuitFileTest
GWAS = GWASTest
rm = rm --f

all: AES LARGE FILE GWAS

AES: $(OBJECTS) $(TESTDIR)/$(AES).c
	$(CC) $(OBJECTFULL) $(TESTDIR)/$(AES).c -o $(BINDIR)/$(AES).out $(LIBS) $(CFLAGS) 

LARGE: $(OBJECTS) $(TESTDIR)/$(LARGE).c
	$(CC) $(OBJECTFULL) $(TESTDIR)/$(LARGE).c -o $(BINDIR)/$(LARGE).out $(LIBS) $(CFLAGS) 

FILE: $(OBJECTS) $(TESTDIR)/$(FILE).c
	$(CC) $(OBJECTFULL) $(TESTDIR)/$(FILE).c -o $(BINDIR)/$(FILE).out $(LIBS) $(CFLAGS) 
	
GWAS: $(OBJECTS) $(TESTDIR)/$(GWAS).c
	$(CC) $(OBJECTFULL) $(TESTDIR)/$(GWAS).c -o $(BINDIR)/$(GWAS).out $(LIBS) $(CFLAGS) 


$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) -c $< -o $@ $(LIBS) $(CFLAGS) 

.PHONEY: clean
clean:
	@$(rm) $(OBJECTS)
	@$(rm) $(BINDIR)/$(AES)
	@$(rm) $(BINDIR)/$(LARGE)
	@$(rm) $(BINDIR)/$(FILE)

