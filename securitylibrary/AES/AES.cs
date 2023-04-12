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
        public string[,] Inv_Sub_Bytes = new string[16, 16] {
               { "52" , "09",  "6a",  "d5",  "30",  "36",  "a5",  "38",  "bf",  "40",  "a3",  "9e",  "81",  "f3",  "d7" , "fb"} ,
               { "7c" , "e3",  "39",  "82",  "9b",  "2f",  "ff",  "87",  "34",  "8e",  "43",  "44",  "c4",  "de",  "e9" , "cb"},
               { "54" , "7b",  "94",  "32",  "a6",  "c2",  "23",  "3d",  "ee",  "4c",  "95",  "0b",  "42",  "fa",  "c3" , "4e"},
               { "08" , "2e",  "a1",  "66",  "28",  "d9",  "24",  "b2",  "76",  "5b",  "a2",  "49",  "6d",  "8b",  "d1" , "25"},
               { "72" , "f8",  "f6",  "64",  "86",  "68",  "98",  "16",  "d4",  "a4",  "5c",  "cc",  "5d",  "65",  "b6" , "92"},
               { "6c" , "70",  "48",  "50",  "fd",  "ed",  "b9",  "da",  "5e",  "15",  "46",  "57",  "a7",  "8d",  "9d" , "84"},
               { "90" , "d8",  "ab",  "00",  "8c",  "bc",  "d3",  "0a",  "f7",  "e4",  "58",  "05",  "b8",  "b3",  "45" , "06"},
               { "d0" , "2c",  "1e",  "8f",  "ca",  "3f",  "0f",  "02",  "c1",  "af",  "bd",  "03",  "01",  "13",  "8a" , "6b"},
               { "3a" , "91",  "11",  "41",  "4f",  "67",  "dc",  "ea",  "97",  "f2",  "cf",  "ce",  "f0",  "b4",  "e6" , "73"},
               { "96" , "ac",  "74",  "22",  "e7",  "ad",  "35",  "85",  "e2",  "f9",  "37",  "e8",  "1c",  "75",  "df" , "6e"},
               { "47" , "f1",  "1a",  "71",  "1d",  "29",  "c5",  "89",  "6f",  "b7",  "62",  "0e",  "aa",  "18",  "be" , "1b"},
               { "fc" , "56",  "3e",  "4b",  "c6",  "d2",  "79",  "20",  "9a",  "db",  "c0",  "fe",  "78",  "cd",  "5a" , "f4"},
               { "1f" , "dd",  "a8",  "33",  "88",  "07",  "c7",  "31",  "b1",  "12",  "10",  "59",  "27",  "80",  "ec" , "5f"},
               { "60" , "51",  "7f",  "a9",  "19",  "b5",  "4a",  "0d",  "2d",  "e5",  "7a",  "9f",  "93",  "c9",  "9c" , "ef"},
               { "a0" , "e0",  "3b",  "4d",  "ae",  "2a",  "f5",  "b0",  "c8",  "eb",  "bb",  "3c",  "83",  "53",  "99" , "61"},
               { "17" , "2b",  "04",  "7e",  "ba",  "77",  "d6",  "26",  "e1",  "69",  "14",  "63",  "55",  "21",  "0c" , "7d"},

        };
        public string[,] mix = new string[4, 4]
        {
            {"2","3","1","1" },
            {"1","2","3","1" },
            {"1","1","2","3" },
            {"3","1","1","2" }
        };
        public string[,] inv_mix = new string[4, 4]
        {
            {"e","b","d","9" },
            {"9","e","b","d" },
            {"d","9","e","b" },
            {"b","d","9","e" }
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

        public Dictionary<int, string> IntilizeKey_XOR(Dictionary<int, string> Key_XOR)
        {
            Key_XOR.Add(1, "01");
            Key_XOR.Add(2, "02");
            Key_XOR.Add(3, "04");
            Key_XOR.Add(4, "08");
            Key_XOR.Add(5, "10");
            Key_XOR.Add(6, "20");
            Key_XOR.Add(7, "40");
            Key_XOR.Add(8, "80");
            Key_XOR.Add(9, "1b");
            Key_XOR.Add(10, "36");

            return Key_XOR;
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
            HexToNum.Add('d', 13);
            HexToNum.Add('e', 14);
            HexToNum.Add('f', 15);
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
        public List<string[,]> expanded_list = new List<string[,]>();
        public char FromBinToHex(string bin, Dictionary<string, char> BinToHex) => BinToHex[bin];
        public string FromHexToBin(char hex, Dictionary<char, string> HexToBin) => HexToBin[hex];
        public int FromHexToNum(char hex, Dictionary<char, int> HexToNum) => HexToNum[hex];
        public string Key_XOR(int round, Dictionary<int, string> Key_XOR) => Key_XOR[round];
        public string XOR(string first, string second)
        {
            string temp = "";
            for (int i = 0; i < first.Length; i++)
                if (first[i].Equals(second[i]))
                    temp = string.Concat(temp, "0");
                else
                    temp = string.Concat(temp, "1");
            return temp;
        }

        public string[,] matrix(string text)
        {
            var result = new string[4, 4];
            int cnt = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    result[i, j] = string.Concat(text[cnt], text[cnt + 1]);
                    cnt += 2;

                }

            }
            return result;
        }
        public string[,] Expanded_Key(string[,] key, int round)
        {
            Dictionary<char, int> HexToNum = new Dictionary<char, int>();
            HexToNum = IntilizeHexToNum(HexToNum);
            Dictionary<char, string> HextoBin = new Dictionary<char, string>();
            HextoBin = IntilizeHexToBin(HextoBin);
            Dictionary<string, char> BinToHex = new Dictionary<string, char>();
            BinToHex = IntilizeBinToHex(BinToHex);
            Dictionary<int, string> Key_XOR = new Dictionary<int, string>();
            Key_XOR = IntilizeKey_XOR(Key_XOR);

            string[,] New_Key = new string[4, 4];

            for (int j = 0; j < 4; j++)
            {
                if (j == 0)
                {
                    for (int y = 0; y < 4; y++)
                    {
                        string temp1 = key[0, 3];
                        for (int k = 0; k < 3; k++)
                        {
                            New_Key[k, 0] = key[k + 1, 3];
                        }
                        New_Key[3, 0] = temp1;
                    }

                    for (int y = 0; y < 4; y++)
                    {

                        string x = New_Key[y, 0];
                        int temp2 = HexToNum[x[0]];
                        int temp3 = HexToNum[x[1]];
                        New_Key[y, 0] = s_box[temp2, temp3];

                    }

                    string rc = Key_XOR[round];
                    string[] RCZero = new string[4] { rc, "00", "00", "00" };

                    for (int y = 0; y < 4; y++)
                    {
                        string index = New_Key[y, 0];
                        string index2 = RCZero[y];
                        string temp2 = XOR(HextoBin[index[0]], HextoBin[index2[0]]);
                        string temp3 = XOR(HextoBin[index[1]], HextoBin[index2[1]]);
                        char temp4 = BinToHex[temp2];
                        char temp5 = BinToHex[temp3];
                        New_Key[y, 0] = string.Concat(temp4, temp5);

                    }
                    for (int y = 0; y < 4; y++)
                    {
                        string index = key[y, 0];
                        string index2 = New_Key[y, 0];
                        string temp2 = XOR(HextoBin[index[0]], HextoBin[index2[0]]);
                        string temp3 = XOR(HextoBin[index[1]], HextoBin[index2[1]]);
                        char temp4 = BinToHex[temp2];
                        char temp5 = BinToHex[temp3];
                        New_Key[y, 0] = string.Concat(temp4, temp5);

                    }

                }
                else
                {
                    for (int i = 0; i < 4; i++)
                    {


                        string index = New_Key[i, j - 1];
                        string index2 = key[i, j];
                        string temp2 = XOR(HextoBin[index[0]], HextoBin[index2[0]]);
                        string temp3 = XOR(HextoBin[index[1]], HextoBin[index2[1]]);
                        char temp4 = BinToHex[temp2];
                        char temp5 = BinToHex[temp3];
                        New_Key[i, j] = string.Concat(temp4, temp5);




                    }

                }
            }

            return New_Key;
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
                    result[i, j] = string.Concat(temp3, temp4);

                }

            }
            return result;
        }

        public string[,] shift_rows(string[,] rounded)
        {
            //first row: no change
            //second row: shift 1 element to the left
            string temp1 = rounded[1, 0];
            for (int i = 0; i < 3; i++)
            {
                rounded[1, i] = rounded[1, i + 1];
            }
            rounded[1, 3] = temp1;
            //third row: shift 2 elements to the left
            temp1 = rounded[2, 0];
            string temp2 = rounded[2, 1];
            rounded[2, 0] = rounded[2, 2];
            rounded[2, 1] = rounded[2, 3];
            rounded[2, 2] = temp1;
            rounded[2, 3] = temp2;
            //fourth row: shift 3 elements to the left
            temp1 = rounded[3, 3];
            for (int i = 3; i > 0; i--)
            {
                rounded[3, i] = rounded[3, i - 1];
            }
            rounded[3, 0] = temp1;
            return rounded;
        }
        public string[,] inv_shift_rows(string[,] rounded)
        {
            //first row: no change
            //second row: shift 1 element to the right
            string temp1 = rounded[1, 3];
            for (int i = 3; i > 0; i--)
            {
                rounded[1, i] = rounded[1, i - 1];
            }
            rounded[1, 0] = temp1;
            //third row: shift 2 elements to the right
            temp1 = rounded[2, 0];
            string temp2 = rounded[2, 1];
            rounded[2, 0] = rounded[2, 2];
            rounded[2, 1] = rounded[2, 3];
            rounded[2, 2] = temp1;
            rounded[2, 3] = temp2;
            //fourth row: shift 3 elements to the right
            temp1 = rounded[3, 0];
            for (int i = 0; i < 3; i++)
            {
                rounded[3, i] = rounded[3, i + 1];
            }
            rounded[3, 3] = temp1;
            return rounded;
        }
        public string[,] inv_mix_columns(string[,] shifted)
        {
            string[,] final = new string[4, 4];
            string[] result = new string[4];
            int cntr1 = 0, cntr2 = 0;
            Dictionary<char, string> HextoBin = new Dictionary<char, string>();
            HextoBin = IntilizeHexToBin(HextoBin);
            Dictionary<string, char> BinToHex = new Dictionary<string, char>();
            BinToHex = IntilizeBinToHex(BinToHex);

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (inv_mix[i, k].Equals("9"))
                        {
                            string temp1 = mix_columns2(shifted[k, j]);
                            string temp2 = shifted[k, j];
                            temp1 = mix_columns2(temp1);
                            temp1 = mix_columns2(temp1);
                            string temp3 = XOR(HextoBin[temp1[0]], HextoBin[temp2[0]]);
                            string temp4 = XOR(HextoBin[temp1[1]], HextoBin[temp2[1]]);
                            char char1 = BinToHex[temp3];
                            char char2 = BinToHex[temp4];
                            result[k] = string.Concat(char1, char2);

                        }
                        else if (inv_mix[i, k].Equals("b"))
                        {
                            string temp1 = mix_columns2(shifted[k, j]);
                            string temp2 = shifted[k, j];
                            temp1 = mix_columns2(temp1);
                            string temp3 = XOR(HextoBin[temp1[0]], HextoBin[temp2[0]]);
                            string temp4 = XOR(HextoBin[temp1[1]], HextoBin[temp2[1]]);
                            char char1 = BinToHex[temp3];
                            char char2 = BinToHex[temp4];
                            result[k] = string.Concat(char1, char2);
                            temp1 = mix_columns2(result[k]);
                            temp3 = XOR(HextoBin[temp1[0]], HextoBin[temp2[0]]);
                            temp4 = XOR(HextoBin[temp1[1]], HextoBin[temp2[1]]);
                            char1 = BinToHex[temp3];
                            char2 = BinToHex[temp4];
                            result[k] = string.Concat(char1, char2);

                        }
                        else if (inv_mix[i, k].Equals("d"))
                        {
                            string temp1 = mix_columns2(shifted[k, j]);
                            string temp2 = shifted[k, j];
                            string temp3 = XOR(HextoBin[temp1[0]], HextoBin[temp2[0]]);
                            string temp4 = XOR(HextoBin[temp1[1]], HextoBin[temp2[1]]);
                            char char1 = BinToHex[temp3];
                            char char2 = BinToHex[temp4];
                            result[k] = string.Concat(char1, char2);
                            temp1 = mix_columns2(result[k]);
                            temp1 = mix_columns2(temp1);
                            temp3 = XOR(HextoBin[temp1[0]], HextoBin[temp2[0]]);
                            temp4 = XOR(HextoBin[temp1[1]], HextoBin[temp2[1]]);
                            char1 = BinToHex[temp3];
                            char2 = BinToHex[temp4];
                            result[k] = string.Concat(char1, char2);
                        }
                        else if (inv_mix[i, k].Equals("e"))
                        {
                            string temp1 = mix_columns2(shifted[k, j]);
                            string temp2 = shifted[k, j];
                            string temp3 = XOR(HextoBin[temp1[0]], HextoBin[temp2[0]]);
                            string temp4 = XOR(HextoBin[temp1[1]], HextoBin[temp2[1]]);
                            char char1 = BinToHex[temp3];
                            char char2 = BinToHex[temp4];
                            result[k] = string.Concat(char1, char2);
                            temp1 = mix_columns2(result[k]);
                            temp3 = XOR(HextoBin[temp1[0]], HextoBin[temp2[0]]);
                            temp4 = XOR(HextoBin[temp1[1]], HextoBin[temp2[1]]);
                            char1 = BinToHex[temp3];
                            char2 = BinToHex[temp4];
                            result[k] = string.Concat(char1, char2);
                            temp1 = mix_columns2(result[k]);
                            result[k] = temp1;
                        }

                    }
                    for (int h = 0; h < 3; h++)
                    {
                        string x = result[h];
                        string y = result[h + 1];
                        string temp1 = XOR(HextoBin[x[0]], HextoBin[y[0]]);
                        string temp2 = XOR(HextoBin[x[1]], HextoBin[y[1]]);
                        char char1 = BinToHex[temp1];
                        char char2 = BinToHex[temp2];
                        result[h + 1] = string.Concat(char1, char2);
                    }
                    final[cntr1, cntr2] = result[3];
                    if (cntr2 == 3)
                    {
                        cntr2 = 0;
                        cntr1++;
                    }
                    else
                    {
                        cntr2++;
                    }
                }
            }

            return final;
        }
        public string[,] mix_columns(string[,] shifted)
        {
            string[,] final = new string[4, 4];
            string[] result = new string[4];
            int cntr1 = 0, cntr2 = 0;
            Dictionary<char, string> HextoBin = new Dictionary<char, string>();
            HextoBin = IntilizeHexToBin(HextoBin);
            Dictionary<string, char> BinToHex = new Dictionary<string, char>();
            BinToHex = IntilizeBinToHex(BinToHex);

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (mix[i, k].Equals("1"))
                        {
                            result[k] = shifted[k, j];
                        }
                        else if (mix[i, k].Equals("2"))
                        {
                            result[k] = mix_columns2(shifted[k, j]);
                        }
                        else if (mix[i, k].Equals("3"))
                        {
                            string temp1 = shifted[k, j];
                            string temp2 = mix_columns2(shifted[k, j]);

                            string temp3 = XOR(HextoBin[temp1[0]], HextoBin[temp2[0]]);
                            string temp4 = XOR(HextoBin[temp1[1]], HextoBin[temp2[1]]);

                            char char1 = BinToHex[temp3];
                            char char2 = BinToHex[temp4];
                            result[k] = string.Concat(char1, char2);
                        }
                    }
                    for (int h = 0; h < 3; h++)
                    {
                        string x = result[h];
                        string y = result[h + 1];
                        string temp1 = XOR(HextoBin[x[0]], HextoBin[y[0]]);
                        string temp2 = XOR(HextoBin[x[1]], HextoBin[y[1]]);
                        char char1 = BinToHex[temp1];
                        char char2 = BinToHex[temp2];
                        result[h + 1] = string.Concat(char1, char2);
                    }
                    final[cntr1, cntr2] = result[3];
                    if (cntr2 == 3)
                    {
                        cntr2 = 0;
                        cntr1++;
                    }
                    else
                    {
                        cntr2++;
                    }
                }
            }

            return final;
        }
        public string mix_columns2(string shifted)
        {
            string result = "";
            Dictionary<char, string> HextoBin = new Dictionary<char, string>();
            HextoBin = IntilizeHexToBin(HextoBin);
            Dictionary<string, char> BinToHex = new Dictionary<string, char>();
            BinToHex = IntilizeBinToHex(BinToHex);
            bool flag = false;
            string x = shifted;
            StringBuilder temp1 = new StringBuilder(HextoBin[x[0]]);
            StringBuilder temp2 = new StringBuilder(HextoBin[x[1]]);
            if (temp1[0].Equals('1'))
            {
                flag = true;
            }
            for (int k = 0; k < 3; k++)
            {
                temp1[k] = temp1[k + 1];
            }
            temp1[3] = temp2[0];
            for (int k = 0; k < 3; k++)
            {
                temp2[k] = temp2[k + 1];
            }
            temp2[3] = '0';
            char temp3, temp4;
            if (flag)
            {
                string t1 = XOR(temp1.ToString(), "0001");
                string t2 = XOR(temp2.ToString(), "1011");
                temp3 = BinToHex[t1];
                temp4 = BinToHex[t2];
                result = string.Concat(temp3, temp4);

            }
            else
            {
                temp3 = BinToHex[temp1.ToString()];
                temp4 = BinToHex[temp2.ToString()];
                result = string.Concat(temp3, temp4);
            }
            return result;
        }

        public string[,] substitute_bytes(string[,] rounded, bool flag)
        {
            Dictionary<char, int> HexToNum = new Dictionary<char, int>();
            HexToNum = IntilizeHexToNum(HexToNum);
            string[,] substitute = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string x = rounded[i, j];
                    int temp1 = HexToNum[x[0]];
                    int temp2 = HexToNum[x[1]];
                    if (flag)
                    {
                        substitute[i, j] = s_box[temp1, temp2];
                    }
                    else
                    {
                        substitute[i, j] = Inv_Sub_Bytes[temp1, temp2];

                    }
                }
            }
            return substitute;
        }
        public string final_result(string[,] final)
        {
            string result = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result = string.Concat(result, final[j, i]);
                }
            }
            return result;
        }

        public override string Encrypt(string plainText, string key)
        {

            string[,] plaintext = matrix(plainText.ToLower());
            string[,] Key = matrix(key.ToLower());
            string[,] Rounded = Round_Key(plaintext, Key);

            for (int i = 1; i < 10; i++)
            {
                string[,] substitute = substitute_bytes(Rounded, true);
                string[,] shifted_rows = shift_rows(substitute);
                string[,] mixed = mix_columns(shifted_rows);
                string[,] expanded = Expanded_Key(Key, i);
                Rounded = Round_Key(mixed, expanded);
                Key = expanded;

            }
            string[,] sub = substitute_bytes(Rounded, true);
            string[,] shifted = shift_rows(sub);
            string[,] expanded_key = Expanded_Key(Key, 10);
            Rounded = Round_Key(shifted, expanded_key);
            string result = final_result(Rounded);


            return result;
        }


        public override string Decrypt(string cipherText, string key)
        {
            string[,] ciphertext = matrix(cipherText.ToLower());
            string[,] Key = matrix(key.ToLower());
            string[,] mixed = new string[4, 4];
            expanded_list.Add(Key);
            for (int i = 1; i <= 10; i++)
            {
                string[,] expanded = Expanded_Key(Key, i);
                expanded_list.Add(expanded);
                Key = expanded;
            }
            string[,] Rounded = Round_Key(ciphertext, expanded_list[10]);
            string[,] shifted_rows = inv_shift_rows(Rounded);
            string[,] substitute = substitute_bytes(shifted_rows, false);
            for (int i = 9; i > 0; i--)
            {
                Rounded = Round_Key(substitute, expanded_list[i]);
                mixed = inv_mix_columns(Rounded);
                shifted_rows = inv_shift_rows(mixed);
                substitute = substitute_bytes(shifted_rows, false);

            }
            Rounded = Round_Key(substitute, expanded_list[0]);
            string result = final_result(Rounded);
            return result;
        }

    }
}