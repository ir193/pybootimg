import boot_img
import unittest
import os
import logging

logging.info("[2] Testing uncompress")

with open('zImage', 'rb') as f:
    data = f.read()
    boot_img.decompress(data)