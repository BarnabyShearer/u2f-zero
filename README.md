Fork of https://github.com/conorpp/u2f-zero for a more compact phisical size.

Changes
=======

* Dual-side load, manufacturability and bulk programming a deprioritized but manual assemble was fine.
* Smaller edge-mounted switch
* Swapped R<>B LEDs due to routing constraint.
* Upgrade UFM8UB11F16 to UFM8UB31F40 (extra flash allows all features to be enabled, more readily available).
* Switch from SimplicityStudio_v3 to SimplicityStudio_v4 (to support new chip)

Images
======

![Render](/u2f-zero.png?raw=true "Render")
![Top](/top.png?raw=true "Top")
![Bottom](/bottom.png?raw=true "Bottom")


Installation
============

(Only tested on Linux)

Install Simlicity Studio 4 and activate the free Keil license.

Set your SDK paths in `Makefile`, and run `./setup_device.py`

This will compile and flash the setup firmware, generate and load
a new certificate, then build and flash the main firmware.
