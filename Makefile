vpath %.exe build/
vpath %.dll build/
vpath %.nim src/ examples/
vpath %.c cache/

CC 			= x86_64-w64-mingw32-gcc
LD			= x86_64-w64-mingw32-ld
BUILD_DIR 	= ./build
CACHE_DIR	= ./cache
RANDOM		:= $(shell bash -c 'echo $$RANDOM')

## Nim Flags 
NFLAGS = --compileOnly -d:mingw -d:danger -d:release -d:nimNoLibc -d:nimBuiltinSetjmp \
-d:noSignalHandler -d:lto -d:noRes --gc:none --threads:off  --cpu:amd64 \
--checks:off --forcebuild --tlsEmulation:off --dynlibOverrideAll --nanChecks:off \
--infChecks:off --stdout:off --hotCodeReloading:off --stackTraceMsgs:off \
--sinkInference:off --deepcopy:off --styleCheck:off --skipParentCfg \
--hints:off -d:HashSeed=$(RANDOM) --noMain:on

## GCC flags
CFLAGS := -w -fmax-errors=3 -mno-ms-bitfields -masm=intel -nostdlib -fpic \
-ffunction-sections -fno-ident -fno-asynchronous-unwind-tables -fno-exceptions \
-fmerge-all-constants -fdata-sections -O2 -Wno-write-strings

## Linker flags 
## -x --relax 
LDFLAGS := -e NimMainModule --gc-sections -s --no-seh --disable-runtime-pseudo-relo  --disable-reloc-section

## Nim Libs
## TODO: dynamically find this lib
## if you're going to use this makefile, make sure to set this!
NIMBASE := -I/home/anon/.choosenim/toolchains/nim-1.6.8/lib
NIMBASE += -I$(shell bash -c 'echo $$PWD')/src
CFLAGS := $(NIMBASE) $(CFLAGS)

## Sources
NIMS 		= $(notdir $(wildcard src/*.nim))
EXMS 		= $(notdir $(wildcard examples/*.nim))
BINS 		= $(NIMS:.nim=.exe)
EXBINS 		= $(EXMS:.nim=.exe)

SRC_FILE 	= $@
BUILD_CACHE = $(CACHE_DIR)/$(subst .exe,,$(SRC_FILE))
BUILD_SRC 	= $(BUILD_DIR)/$(subst .exe,,$(SRC_FILE))
MAIN_FILE 	= $(BUILD_CACHE)/@m$(subst .exe,.nim.c,$(SRC_FILE))
CACHE_INFO 	= $(BUILD_CACHE)/$(subst .exe,.json,$(SRC_FILE))

.PHONY: clean

default: build

clean:
	rm -r cache/*

build: $(BINS)

build_examples: $(EXBINS)

rebuild: clean build

%.exe : %.nim
	@mkdir -p $(BUILD_CACHE)
	@mkdir -p $(BUILD_SRC)
	@echo "[+] Generating C source files for $(SRC_FILE) with RNG Seed $(RANDOM)"
	@nim c $(NFLAGS) --app:gui --nimcache:$(BUILD_CACHE)/ $<
	@sed -i /Init000/d $(MAIN_FILE)
	@for src in $$(cat $(CACHE_INFO) | jq -r .compile[][0]); do \
		echo "[i] compiling $$src"; \
		$(CC) $(CFLAGS) -c "$$src" -o "$$src.o"; \
	done;
	@$(LD) -o $(BUILD_SRC)/$@ $(LDFLAGS) -Map=$(BUILD_SRC)/$@.map \
	$$(cat $(CACHE_INFO) | jq -r '.link | join(" ")')
	
