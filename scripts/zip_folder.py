import zipfile
import sys
import os

def zipdir(path, ziph):
    # ziph is zipfile handle
    curdir = os.curdir
    os.chdir(os.path.join(curdir, path))
    print(curdir)
    print(os.curdir)
    for root, dirs, files in os.walk(os.curdir):
        for file in files:
            ziph.write(os.path.join(root, file))
    os.chdir(curdir)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: %s achivePath folderToArchive")
    else:
        zipf = zipfile.ZipFile(sys.argv[2], 'w', zipfile.ZIP_DEFLATED)
        zipdir(sys.argv[1], zipf)
        zipf.close()