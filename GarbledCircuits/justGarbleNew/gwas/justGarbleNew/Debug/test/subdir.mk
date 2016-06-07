################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../test/AESFullTest.c \
../test/CircuitFileTest.c \
../test/GWASTest.c \
../test/LargeCircuitTest.c 

OBJS += \
./test/AESFullTest.o \
./test/CircuitFileTest.o \
./test/GWASTest.o \
./test/LargeCircuitTest.o 

C_DEPS += \
./test/AESFullTest.d \
./test/CircuitFileTest.d \
./test/GWASTest.d \
./test/LargeCircuitTest.d 


# Each subdirectory must supply rules for building sources it contributes
test/%.o: ../test/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


