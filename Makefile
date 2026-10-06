TARGET := iphone:clang:16.5:14.0
ARCHS  := arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME := chromapatch
chromapatch_FILES := Tweak.x
chromapatch_CFLAGS := -fobjc-arc -O2
chromapatch_FRAMEWORKS := Foundation UIKit
chromapatch_LIBRARIES := substrate

include $(THEOS)/makefiles/tweak.mk
