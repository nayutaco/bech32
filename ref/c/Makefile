LIBNAME = bech32
PROJECT_NAME := lib$(LIBNAME).a
OBJECT_DIRECTORY = _build
PRJ_PATH = 
OBJECT_DIRECTORY = _build
OUTPUT_BINARY_DIRECTORY = .
OUTPUT_FILENAME := $(PROJECT_NAME)

MAKEFILE_NAME := $(MAKEFILE_LIST)
MAKEFILE_DIR := $(dir $(MAKEFILE_NAME) )

#GNU_PREFIX := arm-none-eabi-

MK := mkdir
RM := rm -rf

#echo suspend
ifeq ("$(VERBOSE)","1")
NO_ECHO :=
else
NO_ECHO := @
endif

# Toolchain commands
CC       		:= "$(GNU_PREFIX)gcc"
AS       		:= "$(GNU_PREFIX)as"
AR       		:= "$(GNU_PREFIX)ar" -r
LD       		:= "$(GNU_PREFIX)ld"
NM       		:= "$(GNU_PREFIX)nm"
OBJDUMP  		:= "$(GNU_PREFIX)objdump"
OBJCOPY  		:= "$(GNU_PREFIX)objcopy"
SIZE    		:= "$(GNU_PREFIX)size"

#function for removing duplicates in a list
remduplicates = $(strip $(if $1,$(firstword $1) $(call remduplicates,$(filter-out $(firstword $1),$1))))

#sources project
C_SOURCE_FILES += $(PRJ_PATH)segwit_addr.c

#includes common to all targets
INC_PATHS += -I.

LISTING_DIRECTORY = $(OBJECT_DIRECTORY)

# Sorting removes duplicates
BUILD_DIRECTORIES := $(sort $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY) $(LISTING_DIRECTORY) )

######################################
#CFLAGS
######################################
# cpu
#CFLAGS += -mcpu=cortex-m0
#CFLAGS += -mthumb -mabi=aapcs
#CFLAGS += -mfloat-abi=soft

CFLAGS += --std=c99
CFLAGS += -Wall -Wno-error=unused-function -fno-common

# keep every function in separate section. This will allow linker to dump unused functions
CFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing
#CFLAGS += -flto -fno-builtin


######################################
#LDFLAGS
######################################
# cpu
#LDFLAGS += -mcpu=cortex-m0

# keep every function in separate section. This will allow linker to dump unused functions
#LDFLAGS += -Xlinker -Map=$(LISTING_DIRECTORY)/$(OUTPUT_FILENAME).map

# let linker to dump unused sections
LDFLAGS += -Wl,--gc-sections

# use newlib in nano version
#LDFLAGS += --specs=nano.specs -lc -lnosys

#Link Library
#LIBS += -Llibs$(POSTFIX)


#default target - first one defined
default: .Depend debug

#building all targets
all:
	$(NO_ECHO)$(MAKE) -f $(MAKEFILE_NAME) -C $(MAKEFILE_DIR) -e cleanobj
	$(NO_ECHO)$(MAKE) -f $(MAKEFILE_NAME) -C $(MAKEFILE_DIR) -e debug

#target for printing all targets
help:
	@echo following targets are available:
	@echo 	debug release


C_SOURCE_FILE_NAMES = $(notdir $(C_SOURCE_FILES))
C_PATHS = $(call remduplicates, $(dir $(C_SOURCE_FILES) ) )
C_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(C_SOURCE_FILE_NAMES:.c=.o) )

vpath %.c $(C_PATHS)

OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

debug: CFLAGS += -DDEBUG -DUCOIN_DEBUG -DUCOIN_USE_PRINTFUNC -DUCOIN_DEBUG_MEM
debug: CFLAGS += -ggdb3 -O0
debug: LDFLAGS += -ggdb3 -O0
debug: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [DEBUG]Linking target: $(OUTPUT_FILENAME)
	@echo [DEBUG]CFLAGS=$(CFLAGS)
	$(NO_ECHO)$(AR) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) $(OBJECT_DIRECTORY)/*.o

release: CFLAGS += -DNDEBUG -O3 -Werror
release: LDFLAGS += -O3
release: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [RELEASE]Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(AR) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) $(OBJECT_DIRECTORY)/*.o

## Create build directories
$(BUILD_DIRECTORIES):
	$(MK) $@

# Create objects from C SRC files
$(OBJECT_DIRECTORY)/%.o: %.c
	@echo Compiling C file: $(notdir $<): $(CFLAGS)
	$(NO_ECHO)$(CC) $(CFLAGS) $(INC_PATHS) -c -o $@ $<

# Link
$(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME): $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

cppcheck:
	cppcheck --enable=all --suppress=missingIncludeSystem -D__ORDER_LITTLE_ENDIAN__ -DDEBUG -DUCOIN_DEBUG -DUCOIN_USE_PRINTFUNC -DUCOIN_DEBUG_MEM $(INC_PATHS) $(PRJ_PATH)*.c

clean:
	$(RM) $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) .Depend

test:
	@rm -f tst > /dev/null 2>&1
	@$(NO_ECHO)$(CC) $(CFLAGS) $(INC_PATHS) -o tst tests.c
	@./tst
	@rm tst

################################

.Depend:
	$(foreach SRC,$(C_SOURCE_FILES),$(CC) $(CFLAGS) $(INC_PATHS) -MM -MT $(OBJECT_DIRECTORY)/$(SRC:.c=.o) $(SRC) >> .Depend;)

-include .Depend
