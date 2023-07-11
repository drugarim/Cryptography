#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <memory>

using namespace std;

struct Person
{
    char age[25];
    char first[25];
    char last[25];
    char phone[25];
};

class BinaryData
{
private:
    char age[25];
    char first[25];
    char last[25];
    char phone[25];

public:
    // constructor
    BinaryData() {}

    // destructor
    ~BinaryData() {}

    void SetData(int age, string strFirst, string strLast, string phone)
    {
        sprintf(this->age, "%d", age);
        sprintf(this->first, "%s", strFirst.c_str());
        sprintf(this->last, "%s", strLast.c_str());
        sprintf(this->phone, "%s", phone.c_str());
    }

    void Save(ofstream &of)
    {
        of.write((char *)&age, sizeof(age));
        of.write((char *)&first, sizeof(first));
        of.write((char *)&last, sizeof(last));
        of.write((char *)&phone, sizeof(phone));
    }

    void WriteBinaryFile(string strFile)
    {
        ofstream fs;
        fs.open(strFile, ios::out | ios::binary | ios::app);
        if (!fs.is_open())
        {
            cout << "cannot open file" << strFile << endl;
        }
        else
        {
            this->Save(fs);
        }
        fs.close();
    }

    void ReadBinaryFile(string strFile)
    {
        // declaring an instance of the class Person
        Person p;
        // declare the ifsream for the binaryFile
        ifstream binaryFile;
        // know the size of the stream
        int size = 0;

        binaryFile.open(strFile, ios::in | ios::binary);
        // sets the position of the next character to extract from the input stream
        binaryFile.seekg(0, ios::end);
        // size of the whole binaryFile
        size = (int)binaryFile.tellg();
        // seek back to the begining of the file
        binaryFile.seekg(0, ios::beg);

        // read file
        while (binaryFile.tellg() < size)
        {
            binaryFile.read((char *)p.age, sizeof(p.age));
            binaryFile.read((char *)p.first, sizeof(p.first));
            binaryFile.read((char *)p.last, sizeof(p.last));
            binaryFile.read((char *)p.phone, sizeof(p.phone));

            cout << p.age << "\t" << p.first << "\t" << p.last << "\t" << p.phone << endl;
        }
        binaryFile.close();
    }
};

int main(void)
{
    string strFirst, strLast, strPhone;
    int age;

    // create a unique pointer that points to Binary Data class
    unique_ptr<BinaryData> bd (new BinaryData());

    // ask the user for the information
    cout << "enter age: ";
    cin >> age;
    cout << "enter first name: ";
    cin >> strFirst;
    cout << "enter last name: ";
    cin >> strLast;
    cout << "enter phone number: ";
    cin >> strPhone;

    // set the data
    bd->SetData(age, strFirst, strLast, strPhone);
    // write binaryFile
    bd->WriteBinaryFile("./record.dat");
    // read the binaryFile
    bd->ReadBinaryFile("./record.dat");
}
