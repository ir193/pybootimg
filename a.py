import boot_img
import unittest
import os
import logging

logging.info("[2] Testing uncompress")
for rom in os.listdir('ROM/'):
    print("\n[ ] Testing on {0}".format(rom))
    with open(os.path.join('ROM', rom), 'rb') as f:
        img = boot_img.BootImage(f)
        img.uncompress_kernel()