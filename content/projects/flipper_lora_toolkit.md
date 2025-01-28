+++
title = "Flipper Zero LoRa Toolkit"
author = ""
authorTwitter = "" #do not include @
cover = ""
tags = ["project", "demo", "Flipper", "LoRa"]
keywords = ["project", "demo", "Flipper", "LoRa"]
description = "A project for adding LoRa capabilities to the Flipper Zero"
showFullContent = false
readingTime = false
hideComments = false
+++

# Flipper Zero: LoRa Toolkit App

⚠️ **WARNING** ⚠️<span style="line-height:2;"></span>   
_Unfinished project, This page is only here to showcase what I've done. If your interested in getting codebase or part of it, feel free to [ask](mailto:yocvito.f@pm.me)_


## Brief

A LoRa Receiver/Transmitter app for Flipper Zero, and almost fully configurable !

This app allows to interact with an Heltec ESP32 LoRa (V2) where a custom firmware is installed.

If you are not familiar with LoRa, you can learn more about it [here](https://en.wikipedia.org/wiki/LoRa). You might also want to check [LoRaWAN](https://www.thethingsnetwork.org/docs/lorawan/), the applicative protocol on top of LoRa.

**Main features:**

- Configure LoRa modem
- Recv/Send LoRa frames

**Additionnal "features":**

- Replay received frames
- Save received frames
- Frequency hopping
    - Select frequencies for hopping
- Add custom frequencies (130-1020MHz)
- Extract channel properties (RSSI, SNR, CFO)

<u>***WARN: For educationnal purpose only. Even though this tool doesn't implement any attacks, it can easely be used to disrupt services which use LoRa around you, so be respectfull and use it for your own stuff or educationnal demonstration.***</u>


## Configure project

### Required 
- Flipper Zero (of course !)
- [Heltec ESP32 LoRa (V2)](https://fr.aliexpress.com/w/wholesale-heltec-esp32-lora-v2.html) embedding a SX1276 transceiver ([board info](https://doc.riot-os.org/group__boards__esp32__heltec-lora32-v2.html))
- Arduino IDE (or equivalent like [vscode extension](https://marketplace.visualstudio.com/items?itemName=vsciot-vscode.vscode-arduino))
- `fbt` toolchain (just clone latest [Xtreme Firmware](https://github.com/Flipper-XFW/Xtreme-Firmware) version)

*Note: the reason why we use the Heltec ESP32 (V2) instead of (V3) is because they embed different transceivers. The SX1276 coming with the V2 allows more granularity in configurations and usage of the radio (I'm also more familiar with it). For example, the SX1262 don't allow fetching the Carrier Frequency Offset (CFO) which can be usefull for authentication.*
*For now it is not planned to port the code to the ESP32 V3, but it's possible if the project interest people.*

### ESP32 

Open the `ESP32LoRaToolkit` project in arduino-ide.

Then you need to install Heltec boards & libraries into arduino following [this guide](https://docs.heltec.org/en/node/esp32/esp32_general_docs/quick_start.html) (I recommend installing <u>Via Arduino Board Manager</u>) 

Select the right board (be careful to take the LoRa V2) and the port (should be `/dev/ttyUSBX` on linux).
Finally, flash the firmware to the ESP32 board by pressing right arrow button located on the top left of the window ("Upload" should appears when your mouse is hovering over it).
![Flashing Arduino](/img/flipper_lora/flash_arduino.png)

If the flashing process have been sucessful and you have let `ENABLE_OLED_DISPLAY` set to `1`, then you should see "LoRa Receiver" displayed on the screen.

### Flipper 

Just copy `lora_toolkit` folder to `./applications_user/` in Xtreme firmware directory.

Then use `./fbt launch APPSRC=applications_user/lora_toolkit` to flash the app.

WARNING: You need to update your firmware, at least to the [release version](https://github.com/Flipper-XFW/Xtreme-Firmware/releases/tag/XFW-0053_02022024) where the uart was refactored in OFW.


## Demo

### #1

First is a demonstration of a triggered jammer PoC to highlights that the ESP32 code remains simple enough, and low level, to allows switching from RX to TX and jamming on a hald-duplex system (in perfect conditions). Actually, I added extra functions in the LoRa driver that allow [*LoRa preamble*](https://www.thethingsnetwork.org/docs/lorawan/lora-phy-format/) detection, and it will be relatively simple to add another features because the [**SX1276 transceiver**](/DS_SX1276-7-8-9_W_APP_V7.pdf) is "easy" to configure and interact with.

[![Watch the First demo](https://img.youtube.com/vi/0ejxvojs_gI/hqdefault.jpg)](https://www.youtube.com/embed/0ejxvojs_gI)

**Photo of the setup:**
![Setup demo 1](/img/flipper_lora/setup_demo_1.jpeg)


### #2

The second video shows all the basic features.

[![Watch the Second demo](https://img.youtube.com/vi/Wc4Ek1JKSUk/hqdefault.jpg)](https://www.youtube.com/embed/Wc4Ek1JKSUk)

### #3

The third and last video is about custom frequencies and hopping. It uses [gqrx](https://www.gqrx.dk/) for visualizing LoRa signals and show you can effectively extends the default frequencies.


[![Watch the Third demo](https://img.youtube.com/vi/_OM5C_Y_GhI/hqdefault.jpg)](https://www.youtube.com/embed/_OM5C_Y_GhI)

**Screenshot of GQRX:**
![A LoRa signal sent outside EU frequencies (the default frequencies of the firmware)](/img/flipper_lora/lora_non_regional_freq.png)


*WARNING: I don't have 2 esp32's, so I can't test that LoRa signals sent in custom freqs outside regional frequencies will be correctly decoded at the receiver side.*



