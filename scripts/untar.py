import tarfile
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: untar path")
    else:
        fname = sys.argv[1]
        if fname.endswith("tar.gz") or fname.endswith("tgz"):
            tar = tarfile.open(fname, "r:gz")
            tar.extractall()
            tar.close()