import sys
import pefile

def view_iat(filepath):
    pe = pefile.PE(filepath)

    for iid in pe.DIRECTORY_ENTRY_IMPORT:
        print(iid.dll.decode('utf-8'))

        for api in iid.imports:
            print('\t+ [{:06X}] {}'.format(api.address, api.name.decode('utf-8')))
        
        print()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: {} <PE file>'.format(sys.argv[0]))
        exit(1)

    view_iat(sys.argv[1])