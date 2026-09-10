import os, sys, base64

TARGET = r'\\wsl$\Ubuntu-22.04\home\abishek14\Kyber-6G project latest\Kyber-6G project\Kyber-6G project\KYBER_6G_COMPLETE_PROJECT_DETAILS.txt'

def init_file():
    with open(TARGET, 'w', encoding='utf-8') as f:
        pass
    print('Initialized:', TARGET)

def append_text(txt):
    with open(TARGET, 'a', encoding='utf-8') as f:
        f.write(txt)
    print(f'Appended {len(txt)} chars')

if __name__ == '__main__':
    if sys.argv[1] == 'init':
        init_file()
    elif sys.argv[1] == 'append':
        b64 = sys.argv[2]
        append_text(base64.b64decode(b64).decode('utf-8'))