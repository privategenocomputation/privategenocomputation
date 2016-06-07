################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../test/AESFullTest.c \
../test/AddTest.c \
../test/CircuitFileTest.c \
../test/CombLinTest.c \
../test/GWASTest.c \
../test/LargeCircuitTest.c \
../test/MulTest.c \
../test/XOR1BitTest.c \
../test/XOR8BitTest.c \
../test/crypto.c 

OBJS += \
./test/AESFullTest.o \
./test/AddTest.o \
./test/CircuitFileTest.o \
./test/CombLinTest.o \
./test/GWASTest.o \
./test/LargeCircuitTest.o \
./test/MulTest.o \
./test/XOR1BitTest.o \
./test/XOR8BitTest.o \
./test/crypto.o 

C_DEPS += \
./test/AESFullTest.d \
./test/AddTest.d \
./test/CircuitFileTest.d \
./test/CombLinTest.d \
./test/GWASTest.d \
./test/LargeCircuitTest.d \
./test/MulTest.d \
./test/XOR1BitTest.d \
./test/XOR8BitTest.d \
./test/crypto.d 


# Each subdirectory must supply rules for building sources it contributes
test/%.o: ../test/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


