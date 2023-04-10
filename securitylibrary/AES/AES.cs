using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
       public string[,] s_box = new string[16, 16] {
               { "63" , "7c",  "77",  "7b",  "f2",  "6b",  "6f",  "c5",  "30",  "01",  "67",  "2b",  "fe",  "d7",  "ab" , "76"} ,
               { "ca" , "82",  "c9",  "7d",  "fa",  "59",  "47",  "f0",  "ad",  "d4",  "a2",  "af",  "9c",  "a4",  "72" , "c0"},
               { "b7" , "fd",  "93",  "26",  "36",  "3f",  "f7",  "cc",  "34",  "a5",  "e5",  "f1",  "71",  "d8",  "31" , "15"},
               { "04" , "c7",  "23",  "c3",  "18",  "96",  "05",  "9a",  "07",  "12",  "80",  "e2",  "eb",  "27",  "b2" , "75"},
               { "09" , "83",  "2c",  "1a",  "1b",  "6e",  "5a",  "a0",  "52",  "3b",  "d6",  "b3",  "29",  "e3",  "2f" , "84"},
               { "53" , "d1",  "00",  "ed",  "20",  "fc",  "b1",  "5b",  "6a",  "cb",  "be",  "39",  "4a",  "4c",  "58" , "cf"},
               { "d0" , "ef",  "aa",  "fb",  "43",  "4d",  "33",  "85",  "45",  "f9",  "02",  "7f",  "50",  "3c",  "9f" , "a8"},
               { "51" , "a3",  "40",  "8f",  "92",  "9d",  "38",  "f5",  "bc",  "b6",  "da",  "21",  "10",  "ff",  "f3" , "d2"},
               { "cd" , "0c",  "13",  "ec",  "5f",  "97",  "44",  "17",  "c4",  "a7",  "7e",  "3d",  "64",  "5d",  "19" , "73"},
               { "60" , "81",  "4f",  "dc",  "22",  "2a",  "90",  "88",  "46",  "ee",  "b8",  "14",  "de",  "5e",  "0b" , "db"},
               { "e0" , "32",  "3a",  "0a",  "49",  "06",  "24",  "5c",  "c2",  "d3",  "ac",  "62",  "91",  "95",  "e4" , "79"},
               { "e7" , "c8",  "37",  "6d",  "8d",  "d5",  "4e",  "a9",  "6c",  "56",  "f4",  "ea",  "65",  "7a",  "ae" , "08"},
               { "ba" , "78",  "25",  "2e",  "1c",  "a6",  "b4",  "c6",  "e8",  "dd",  "74",  "1f",  "4b",  "bd",  "8b" , "8a"},
               { "70" , "3e",  "b5",  "66",  "48",  "03",  "f6",  "0e",  "61",  "35",  "57",  "b9",  "86",  "c1",  "1d" , "9e"},
               { "e1" , "f8",  "98",  "11",  "69",  "d9",  "8e",  "94",  "9b",  "1e",  "87",  "e9",  "ce",  "55",  "28" , "df"},
               { "8c" , "a1",  "89",  "0d",  "bf",  "e6",  "42",  "68",  "41",  "99",  "2d",  "0f",  "b0",  "54",  "bb" , "16"},

        };

        public Dictionary<string, char> IntilizeBinToHex(Dictionary<string, char> BinToHex)
        {
            BinToHex.Add("0000", '0');
            BinToHex.Add("0001", '1');
            BinToHex.Add("0010", '2');
            BinToHex.Add("0011", '3');
            BinToHex.Add("0100", '4');
            BinToHex.Add("0101", '5');
            BinToHex.Add("0110", '6');
            BinToHex.Add("0111", '7');
            BinToHex.Add("1000", '8');
            BinToHex.Add("1001", '9');
            BinToHex.Add("1010", 'a');
            BinToHex.Add("1011", 'b');
            BinToHex.Add("1100", 'c');
            BinToHex.Add("1101", 'd');
            BinToHex.Add("1110", 'e');
            BinToHex.Add("1111", 'f');
            return BinToHex;
        }
        public Dictionary<char, int> IntilizeHexToNum(Dictionary<char, int> HexToNum)
        {
            HexToNum.Add('0', 0);
            HexToNum.Add('1', 1);
            HexToNum.Add('2', 2);
            HexToNum.Add('3', 3);
            HexToNum.Add('4', 4);
            HexToNum.Add('5', 5);
            HexToNum.Add('6', 6);
            HexToNum.Add('7', 7);
            HexToNum.Add('8', 8);
            HexToNum.Add('9', 9);
            HexToNum.Add('a', 10);
            HexToNum.Add('b', 11);
            HexToNum.Add('c', 12);
            HexToNum.Add('d',13);
            HexToNum.Add('e', 14);
            HexToNum.Add('f',15);
            return HexToNum;
        }
        public Dictionary<char, string> IntilizeHexToBin(Dictionary<char, string> HexToBin)
        {
            HexToBin.Add('0', "0000");
            HexToBin.Add('1', "0001");
            HexToBin.Add('2', "0010");
            HexToBin.Add('3', "0011");
            HexToBin.Add('4', "0100");
            HexToBin.Add('5', "0101");
            HexToBin.Add('6', "0110");
            HexToBin.Add('7', "0111");
            HexToBin.Add('8', "1000");
            HexToBin.Add('9', "1001");
            HexToBin.Add('a', "1010");
            HexToBin.Add('b', "1011");
            HexToBin.Add('c', "1100");
            HexToBin.Add('d', "1101");
            HexToBin.Add('e', "1110");
            HexToBin.Add('f', "1111");
            return HexToBin;
        }
        public char FromBinToHex(string bin, Dictionary<string, char> BinToHex) => BinToHex[bin];
        public string FromHexToBin(char hex, Dictionary<char, string> HexToBin) => HexToBin[hex];
        public int FromHexToNum(char hex, Dictionary<char, int> HexToNum) => HexToNum[hex];
        public string XOR(string first, string second)
        {
            string temp ="";
            for (int i = 0; i < first.Length; i++)
                if (first[i].Equals(second[i]))
                    temp = string.Concat(temp,"0");
                else
                    temp = string.Concat(temp, "1");
            return temp;
        }

        public string[,] matrix(string text)
        {
            var result = new string[4,4];
            int cnt= 2;
            for(int j = 0; j < 4; j++)
            {
                for(int i = 0; i < 4; i++)
                {
                    result[i, j] =  string.Concat(text[cnt], text[cnt++]);
                    cnt++;
                  
                }
               
            }
            return result;
        }
        public string[,] Round_Key(string[,] Text, string[,] key)
        {


            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string x = Text[i, j];
                    string y = key[i, j];
                    Dictionary<char, string> HextoBin = new Dictionary<char, string>();
                    HextoBin = IntilizeHexToBin(HextoBin);
                    Dictionary<string, char> BinToHex = new Dictionary<string, char>();
                    BinToHex = IntilizeBinToHex(BinToHex);
                     string temp1 = XOR(HextoBin[x[0]], HextoBin[y[0]]);
                     string temp2 = XOR(HextoBin[x[1]], HextoBin[y[1]]);
                     char temp3 = BinToHex[temp1];
                     char temp4 = BinToHex[temp2];
                    result[i,j]= string.Concat(temp3, temp4);
                  
                }

            }  
            
            return result ;
        }




        public override string Encrypt(string plainText, string key)
        {
          string [,] plaintext=  matrix(plainText.ToLower());
          string [,] Key= matrix(key.ToLower());
          string[,] Rounded= Round_Key(plaintext, Key);
            Dictionary<char, int> HexToNum = new Dictionary<char, int>();
            HexToNum = IntilizeHexToNum(HexToNum);
            string[,] substitute = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {

                for (int j = 0; j < 4; j++)
                {
                    string x = Rounded[i, j];
                    int temp1 = HexToNum[x[0]];
                    int temp2 = HexToNum[x[1]];
                    substitute[i,j] =s_box[temp1, temp2];
                    Console.WriteLine(Rounded[i, j]);
                    Console.WriteLine(HexToNum[x[0]]);
                    Console.WriteLine(temp2);
                    Console.WriteLine(substitute[i, j]);





                }
            }


                    return plainText;

        }








        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

       
    }
}