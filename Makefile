CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra -std=c11
PKG_CFLAGS := $(shell pkg-config --cflags jansson libmicrohttpd 2>/dev/null)
PKG_LIBS := $(shell pkg-config --libs jansson libmicrohttpd 2>/dev/null)
INCLUDES := -Iinclude -Isrc -I/opt/homebrew/include -I/usr/local/include $(PKG_CFLAGS)
USE_LOCAL_CRYPTO ?= 0
LOCAL_CRYPTO_LIBS :=
ifeq ($(USE_LOCAL_CRYPTO),1)
LOCAL_CRYPTO_LIBS += -Llib
endif
LDLIBS := $(LOCAL_CRYPTO_LIBS) -L/opt/homebrew/lib -L/usr/local/lib -lcrypto -lssl -lgmssl $(PKG_LIBS) -ljansson -lmicrohttpd
TARGET := bin/sm2_server
SRCS := src/app.c \
	src/endpoints/http_utils.c \
	src/endpoints/dispatcher.c \
	src/endpoints/init_endpoint.c \
	src/endpoints/group_endpoint.c \
	src/endpoints/sign_endpoint.c \
	src/endpoints/verify_endpoint.c \
	src/runtime_state.c \
	src/SM2.c \
	src/SM2_Multi_party_collaborative_signature.c \
	src/crypto/gmssl3_adapter.c

.PHONY: all clean run run-frontend test asan

all: $(TARGET)

$(TARGET): $(SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS) $(LDLIBS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	./scripts/regression_sm2_flow.sh

asan:
	@mkdir -p bin
	$(CC) -g -O1 -fsanitize=address -fno-omit-frame-pointer $(INCLUDES) $(SRCS) $(LDLIBS) -o $(TARGET)_asan

run-frontend:
	python3 -m http.server --directory src 8080

clean:
	rm -rf bin
