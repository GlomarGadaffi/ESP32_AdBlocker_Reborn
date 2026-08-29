cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Version string = version.txt + board tag, e.g. "1.2.0+waveshare-s3-eth".
# It lands in esp_app_desc_t.version (boot log, web UI, and — the reason for
# the tag — readable off the flash by the browser flasher in docs/flasher/,
# which uses it to pick the right release asset for the board it's plugged
# into). Board IDs must match tools/make-release.ps1 and the release
# manifest.json. PROJECT_VER has to be set before project(), i.e. before
# Kconfig is processed, so the board is read straight from the sdkconfig
# file (the one -DSDKCONFIG= names, else ./sdkconfig).
# Re-run configure when version.txt changes, else a bump only lands after a
# manual `idf.py reconfigure` (the 1.2.1 images were tagged 1.2.0 that way).
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/version.txt")
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/version.txt" ADBLOCK_BASE_VER LIMIT_COUNT 1)
string(STRIP "${ADBLOCK_BASE_VER}" ADBLOCK_BASE_VER)
set(ADBLOCK_BOARD_TAG "t-eth-elite")
set(_adblock_sdkconfig "${SDKCONFIG}")
if(NOT _adblock_sdkconfig)
    set(_adblock_sdkconfig "${CMAKE_CURRENT_LIST_DIR}/sdkconfig")
elseif(NOT IS_ABSOLUTE "${_adblock_sdkconfig}")
    set(_adblock_sdkconfig "${CMAKE_CURRENT_LIST_DIR}/${_adblock_sdkconfig}")
endif()
if(EXISTS "${_adblock_sdkconfig}")
    file(STRINGS "${_adblock_sdkconfig}" _ws_line REGEX "^CONFIG_ADBLOCK_BOARD_WAVESHARE_S3_ETH=y")
    if(_ws_line)
        set(ADBLOCK_BOARD_TAG "waveshare-s3-eth")
    endif()
endif()
# On the very first configure the sdkconfig doesn't exist yet — it's generated
# from SDKCONFIG_DEFAULTS after this point — so also honour the board overlay
# named there.
if("${SDKCONFIG_DEFAULTS}" MATCHES "waveshare")
    set(ADBLOCK_BOARD_TAG "waveshare-s3-eth")
endif()
set(PROJECT_VER "${ADBLOCK_BASE_VER}+${ADBLOCK_BOARD_TAG}")

# Guard against the two build dirs sharing one sdkconfig. build-waveshare/
# was once configured with SDKCONFIG=sdkconfig (the root file): every
# reconfigure then rewrote the T-ETH-Elite config with the Waveshare board
# selected, and the next `idf.py build` produced a "LilyGO" image with the
# Waveshare W5500 pin map — Ethernet dead on the board it was flashed to.
# A Waveshare build dir must point at its own sdkconfig file.
if(CMAKE_BINARY_DIR MATCHES "waveshare" AND NOT "${_adblock_sdkconfig}" MATCHES "waveshare")
    message(FATAL_ERROR "build dir ${CMAKE_BINARY_DIR} would use ${_adblock_sdkconfig}. "
        "Configure it with: idf.py -B build-waveshare \"-DSDKCONFIG=<abs path>/sdkconfig.waveshare\" "
        "\"-DSDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.board.waveshare-s3-eth\" build")
endif()
message(STATUS "ESP32_AdBlocker_Reborn version: ${PROJECT_VER} (from ${_adblock_sdkconfig})")

project(dns-sink)
