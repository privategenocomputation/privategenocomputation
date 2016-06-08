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
CFLAGS= -O3 -lm -lrt -lpthread -maes -msse4 -lmsgpackc -lssl -lcrypto -march=native -I$(IDIR)


GWAS = MultyPartyPhenotypeTest
GWAS2 = MultyPartyGWASTest
GWAS3 = MultyPartyAncestryTest
GWAS4 = MultyPartySumLinTest
rm = rm --f

all: GWAS GWAS2 GWAS3 GWAS4

GWAS: $(OBJECTS) $(TESTDIR)/$(GWAS).c
	$(CC) $(OBJECTFULL) $(TESTDIR)/$(GWAS).c -o $(BINDIR)/$(GWAS).out $(LIBS) $(CFLAGS) 

GWAS2: $(OBJECTS) $(TESTDIR)/$(GWAS2).c
	$(CC) $(OBJECTFULL) $(TESTDIR)/$(GWAS2).c -o $(BINDIR)/$(GWAS2).out $(LIBS) $(CFLAGS) 

GWAS3: $(OBJECTS) $(TESTDIR)/$(GWAS3).c
	$(CC) $(OBJECTFULL) $(TESTDIR)/$(GWAS3).c -o $(BINDIR)/$(GWAS3).out $(LIBS) $(CFLAGS) 
	
GWAS4: $(OBJECTS) $(TESTDIR)/$(GWAS4).c
	$(CC) $(OBJECTFULL) $(TESTDIR)/$(GWAS4).c -o $(BINDIR)/$(GWAS4).out $(LIBS) $(CFLAGS) 
	


$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) -c $< -o $@ $(LIBS) $(CFLAGS) 

.PHONEY: clean
clean:
	@$(rm) $(OBJECTS)
	@$(rm) $(BINDIR)/$(AES)
	@$(rm) $(BINDIR)/$(LARGE)
	@$(rm) $(BINDIR)/$(FILE)

