################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../msgpack-1.4.1/example/c/lib_buffer_unpack.c \
../msgpack-1.4.1/example/c/simple_c.c \
../msgpack-1.4.1/example/c/speed_test_uint32_array.c \
../msgpack-1.4.1/example/c/speed_test_uint64_array.c \
../msgpack-1.4.1/example/c/user_buffer_unpack.c 

OBJS += \
./msgpack-1.4.1/example/c/lib_buffer_unpack.o \
./msgpack-1.4.1/example/c/simple_c.o \
./msgpack-1.4.1/example/c/speed_test_uint32_array.o \
./msgpack-1.4.1/example/c/speed_test_uint64_array.o \
./msgpack-1.4.1/example/c/user_buffer_unpack.o 

C_DEPS += \
./msgpack-1.4.1/example/c/lib_buffer_unpack.d \
./msgpack-1.4.1/example/c/simple_c.d \
./msgpack-1.4.1/example/c/speed_test_uint32_array.d \
./msgpack-1.4.1/example/c/speed_test_uint64_array.d \
./msgpack-1.4.1/example/c/user_buffer_unpack.d 


# Each subdirectory must supply rules for building sources it contributes
msgpack-1.4.1/example/c/%.o: ../msgpack-1.4.1/example/c/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


