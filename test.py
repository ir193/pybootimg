
import unittest
import os
import boot_img

class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        pass


    def test_unpack(self):
        # make sure the shuffled sequence does not lose any elements
        for i in os.listdir('ROM/'):
            with open(os.path.join('ROM/', i), 'rb') as f:
                boot_img.BootImage(f)

    def test_decompress(self):
        for i in os.listdir('ROM/'):
            with open(os.path.join('ROM/', i), 'rb') as f:
                img = boot_img.BootImage(f) 
                img.decompress_kernel()

    def test_kallsyms(self):
        for i in os.listdir('ROM/'):
            with open(os.path.join('ROM/', i), 'rb') as f:
                img = boot_img.BootImage(f) 
                d = img.decompress_kernel()
                boot_img.KernelSyms(d)

if __name__ == '__main__':
    unittest.main()