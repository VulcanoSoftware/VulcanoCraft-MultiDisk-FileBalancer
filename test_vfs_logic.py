import os
import shutil
import yaml
import time
from vulcanocraft_multidisk_filebalancer import set_vfs_base_paths, list_virtual_dir

def test():
    for d in ['src1', 'src2', 'disk1']:
        if os.path.exists(d): shutil.rmtree(d)
        os.makedirs(d, exist_ok=True)

    with open('src1/file1.txt', 'w') as f: f.write('1')
    with open('src2/file2.txt', 'w') as f: f.write('2')
    with open('disk1/file3.txt', 'w') as f: f.write('3')

    paths = [os.path.abspath('src1'), os.path.abspath('src2'), os.path.abspath('disk1')]
    set_vfs_base_paths(paths)

    print(f"VFS paths: {paths}")
    res = list_virtual_dir('/')
    print(f"Listing root: {res}")

    shutil.rmtree('src1')
    shutil.rmtree('src2')
    shutil.rmtree('disk1')

if __name__ == "__main__":
    test()
