# ============================================================================
# μCore (mucore-kernel) — Freestanding Kernel & Host FCIS Verification Build
# ============================================================================

CXX      ?= clang++
AS       ?= clang
LD       ?= ld

BUILD_DIR := build
INCLUDES  := -Iinclude -I.

# Strict "No Hidden Mechanisms" C++23 Dialect Flags
COMMON_CXXFLAGS := \
	-std=c++23 \
	-O2 \
	-Wall -Wextra -Werror -Wpedantic \
	-fno-exceptions \
	-fno-rtti \
	-fno-threadsafe-statics

# Bare-Metal Ring-0 x86_64 Kernel Flags (Zero FPU/SSE clobber, Higher-Half -2GiB)
KERNEL_CXXFLAGS := \
	$(COMMON_CXXFLAGS) \
	$(INCLUDES) \
	-ffreestanding \
	-fno-use-cxa-atexit \
	-fno-stack-protector \
	-fno-pic -fno-pie \
	-mno-red-zone \
	-mno-mmx -mno-sse -mno-sse2 \
	-mcmodel=kernel

KERNEL_LDFLAGS := \
	-nostdlib \
	-static \
	-z max-page-size=0x1000 \
	-T kernel/arch/x86_64/linker.ld

HOST_CXXFLAGS := \
	$(COMMON_CXXFLAGS) \
	$(INCLUDES) \
	-pthread

KERNEL_ELF := $(BUILD_DIR)/mucore-x86_64.elf
TEST_BIN   := $(BUILD_DIR)/mucore-tests

# The kernel is header-only apart from three translation units: rebuild them when any header changes.
HEADERS := $(shell find include kernel tests -name '*.hpp')

.PHONY: all kernel test check clean

all: kernel test

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/boot.o: kernel/arch/x86_64/boot.S | $(BUILD_DIR)
	$(CXX) -mcmodel=kernel -fno-pic -fno-pie -c $< -o $@

$(BUILD_DIR)/kmain.o: kernel/kmain.cpp $(HEADERS) | $(BUILD_DIR)
	$(CXX) $(KERNEL_CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/constexpr_proofs_kern.o: tests/constexpr_proofs.cpp $(HEADERS) | $(BUILD_DIR)
	$(CXX) $(KERNEL_CXXFLAGS) -c $< -o $@

$(KERNEL_ELF): $(BUILD_DIR)/boot.o $(BUILD_DIR)/kmain.o $(BUILD_DIR)/constexpr_proofs_kern.o kernel/arch/x86_64/linker.ld
	$(LD) $(KERNEL_LDFLAGS) $(BUILD_DIR)/boot.o $(BUILD_DIR)/kmain.o $(BUILD_DIR)/constexpr_proofs_kern.o -o $@
	@echo "[BUILD] Built bare-metal higher-half ELF64 kernel: $@"

kernel: $(KERNEL_ELF)

$(TEST_BIN): tests/test_main.cpp tests/constexpr_proofs.cpp $(HEADERS) | $(BUILD_DIR)
	$(CXX) $(HOST_CXXFLAGS) tests/test_main.cpp tests/constexpr_proofs.cpp -o $@

test: $(TEST_BIN)
	@./$(TEST_BIN)

check: all

clean:
	rm -rf $(BUILD_DIR)
