################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/aes.c \
../src/aescircuits.c \
../src/check.c \
../src/circuits.c \
../src/dkcipher.c \
../src/eval.c \
../src/garble.c \
../src/gates.c \
../src/scd.c \
../src/util.c 

OBJS += \
./src/aes.o \
./src/aescircuits.o \
./src/check.o \
./src/circuits.o \
./src/dkcipher.o \
./src/eval.o \
./src/garble.o \
./src/gates.o \
./src/scd.o \
./src/util.o 

C_DEPS += \
./src/aes.d \
./src/aescircuits.d \
./src/check.d \
./src/circuits.d \
./src/dkcipher.d \
./src/eval.d \
./src/garble.d \
./src/gates.d \
./src/scd.d \
./src/util.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


