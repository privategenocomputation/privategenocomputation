################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include test/subdir.mk
-include src/subdir.mk
-include scd/subdir.mk
-include obj/subdir.mk
-include msgpack-1.4.1/src/.libs/subdir.mk
-include msgpack-1.4.1/src/subdir.mk
-include msgpack-1.4.1/example/c/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: justGarbleNew

# Tool invocations
justGarbleNew: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: Cross GCC Linker'
	gcc  -o "justGarbleNew" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) justGarbleNew
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
