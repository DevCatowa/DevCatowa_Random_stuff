#!/bin/bash

wget https://raw.githubusercontent.com/DevCat3/DevCatowa_Random_stuff/refs/heads/main/T509/drm_atomic.c
wget https://raw.githubusercontent.com/DevCat3/DevCatowa_Random_stuff/refs/heads/main/T509/patch_sprd_drm.py
chmod +xrw drm_atomic.c
chmod +xrw patch_sprd_drm.py
rm drivers/gpu/drm/drm_atomic.c
mv drm_atomic.c drivers/gpu/drm/
python3 patch_sprd_drm.py
