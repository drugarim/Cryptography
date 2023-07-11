#include <iostream>
#include <fstream>

using namespace std;

void xor_cipher(char *in_filename, char *out_filename, char key)
{
    // opens the file
    fstream input_file, out_file;
    input_file.open(in_filename, ios::in);
    out_file.open(out_filename, ios::out);

    char line[100];

    // ENCRYPTION
    while (!input_file.eof())
    {
        input_file.read(line, 100);
        // the encryption of the key using the XOR cipher
        int i;
        for (i = 0; i < 100; i++)
        {
            if (line[i] == '\0')
                break;
            line[i] ^= key;
        }
        out_file.write(line, i);
    }

    input_file.close();

    // DECRYPTION
    while (!out_file.eof())
    {
        out_file.read(line, 100);
        // the encryption of the key using the XOR cipher
        int i;
        for (i = 0; i < 100; i++)
        {
            if (line[i] == '\0')
                break;
            line[i] ^= key;
        }
        // out_file.write(line, i);
        cout << line << endl;
    }

    out_file.close();
}

int main()
{

    // file is created
    // char in_filename[20];
    // char out_filename[20];
    char file_names[2][20];
    char key;

    // this will prompt the user for file name that exist to be encrypted
    cout << "Enter the name of the file you want to encrypt: " << endl;
    // cin >> in_filename;
    cin >> file_names[0];
    cout << "Enter the name of the output file: " << endl;
    cin >> file_names[1];
    cout << "Enter a single word that will be used to encrypt and decrypt the file: " << endl;
    cin >> key;

    // reads the contents in the file
    xor_cipher(file_names[0], file_names[1], key);


    // using the vigenere cipher

    // save the encrypted data in the given file
    // file.open(file_name, ios::out);
    // file << line;
    // file.close();

    // cout << "File has been encrypted successfully!" << endl;

    return 0;
}
