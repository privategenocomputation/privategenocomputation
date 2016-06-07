################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../msgpack-1.4.1/src/objectc.c \
../msgpack-1.4.1/src/unpack.c \
../msgpack-1.4.1/src/version.c \
../msgpack-1.4.1/src/vrefbuffer.c \
../msgpack-1.4.1/src/zone.c 

O_SRCS += \
../msgpack-1.4.1/src/objectc.o \
../msgpack-1.4.1/src/unpack.o \
../msgpack-1.4.1/src/version.o \
../msgpack-1.4.1/src/vrefbuffer.o \
../msgpack-1.4.1/src/zone.o 

OBJS += \
./msgpack-1.4.1/src/objectc.o \
./msgpack-1.4.1/src/unpack.o \
./msgpack-1.4.1/src/version.o \
./msgpack-1.4.1/src/vrefbuffer.o \
./msgpack-1.4.1/src/zone.o 

C_DEPS += \
./msgpack-1.4.1/src/objectc.d \
./msgpack-1.4.1/src/unpack.d \
./msgpack-1.4.1/src/version.d \
./msgpack-1.4.1/src/vrefbuffer.d \
./msgpack-1.4.1/src/zone.d 


# Each subdirectory must supply rules for building sources it contributes
msgpack-1.4.1/src/%.o: ../msgpack-1.4.1/src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


