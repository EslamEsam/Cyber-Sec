﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

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
            BinToHex.Add("1010", 'A');
            BinToHex.Add("1011", 'B');
            BinToHex.Add("1100", 'C');
            BinToHex.Add("1101", 'D');
            BinToHex.Add("1110", 'E');
            BinToHex.Add("1111", 'F');
            return BinToHex;
        }
        public Dictionary<int, string> IntilizeNumToBin(Dictionary<int, string> NumToBin)
        {
            NumToBin.Add(0, "0000");
            NumToBin.Add(1, "0001");
            NumToBin.Add(2, "0010");
            NumToBin.Add(3, "0011");
            NumToBin.Add(4, "0100");
            NumToBin.Add(5, "0101");
            NumToBin.Add(6, "0110");
            NumToBin.Add(7, "0111");
            NumToBin.Add(8, "1000");
            NumToBin.Add(9, "1001");
            NumToBin.Add(10, "1010");
            NumToBin.Add(11, "1011");
            NumToBin.Add(12, "1100");
            NumToBin.Add(13, "1101");
            NumToBin.Add(14, "1110");
            NumToBin.Add(15, "1111");
            return NumToBin;
        }
        public Dictionary<string, int> IntilizeBinToNum(Dictionary<string, int> binToNum)
        {
            binToNum.Add("00", 0);
            binToNum.Add("01", 1);
            binToNum.Add("10", 2);
            binToNum.Add("11", 3);
            binToNum.Add("0000", 0);
            binToNum.Add("0001", 1);
            binToNum.Add("0010", 2);
            binToNum.Add("0011", 3);
            binToNum.Add("0100", 4);
            binToNum.Add("0101", 5);
            binToNum.Add("0110", 6);
            binToNum.Add("0111", 7);
            binToNum.Add("1000", 8);
            binToNum.Add("1001", 9);
            binToNum.Add("1010", 10);
            binToNum.Add("1011", 11);
            binToNum.Add("1100", 12);
            binToNum.Add("1101", 13);
            binToNum.Add("1110", 14);
            binToNum.Add("1111", 15);
            return binToNum;
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
            HexToBin.Add('A', "1010");
            HexToBin.Add('B', "1011");
            HexToBin.Add('C', "1100");
            HexToBin.Add('D', "1101");
            HexToBin.Add('E', "1110");
            HexToBin.Add('F', "1111");
            return HexToBin;
        }
        public char FromBinToHex(string bin, Dictionary<string, char> BinToHex) => BinToHex[bin];
        public string FromHexToBin(char hex, Dictionary<char, string> HexToBin) => HexToBin[hex];
        public string FromNumToBin(int num, Dictionary<int, string> NumToBin) => NumToBin[num];
        public int FromBinToNum(string bin, Dictionary<string, int> binToNum) => binToNum[bin];

        public int[] Permutation(int[] dataBlock, int number)
        {

            int[] IP =
            {            58, 50, 42, 34, 26, 18, 10,  2,
                         60, 52, 44, 36, 28, 20, 12,  4,
                         62, 54, 46, 38, 30, 22, 14,  6,
                         64, 56, 48, 40, 32, 24, 16,  8,
                         57, 49, 41, 33, 25, 17,  9,  1,
                         59, 51, 43, 35, 27, 19, 11,  3,
                         61, 53, 45, 37, 29, 21, 13,  5,
                         63, 55, 47, 39, 31, 23, 15,  7,
        };
            int[] PC1 =
            {             57, 49, 41, 33, 25, 17, 9,
                           1, 58, 50, 42, 34, 26, 18,
                          10,  2, 59, 51, 43, 35, 27,
                          19, 11,  3, 60, 52, 44, 36,
                          63, 55, 47, 39, 31, 23, 15,
                           7, 62, 54, 46, 38, 30, 22,
                          14,  6, 61, 53, 45, 37, 29,
                          21, 13,  5, 28, 20, 12,  4,
        };
            int[] PC2 =
            {             14, 17, 11, 24, 1,   5,
                           3, 28, 15,  6, 21, 10,
                          23, 19, 12,  4, 26,  8,
                          16,  7, 27, 20, 13,  2,
                          41, 52, 31, 37, 47, 55,
                          30, 40, 51, 45, 33, 48,
                          44, 49, 39, 56, 34, 53,
                          46, 42, 50, 36, 29, 32,
        };
            int[] EP =
            {            32,  1,  2,  3,  4,  5,
                          4,  5,  6,  7,  8,  9,
                          8,  9, 10, 11, 12, 13,
                         12, 13, 14, 15, 16, 17,
                         16, 17, 18, 19, 20, 21,
                         20, 21, 22, 23, 24, 25,
                         24, 25, 26, 27, 28, 29,
                         28, 29, 30, 31, 32,  1,
        };
            int[] P =
            {
                        16,  7, 20, 21,
                        29, 12, 28, 17,
                         1, 15, 23, 26,
                         5, 18, 31, 10,
                         2,  8, 24, 14,
                        32, 27,  3,  9,
                        19, 13, 30,  6,
                        22, 11,  4, 25,
            };
            int[] IPInverse =
            {
                      40, 8, 48, 16, 56, 24, 64, 32,
                      39, 7, 47, 15, 55, 23, 63, 31,
                      38, 6, 46, 14, 54, 22, 62, 30,
                      37, 5, 45, 13, 53, 21, 61, 29,
                      36, 4, 44, 12, 52, 20, 60, 28,
                      35, 3, 43, 11, 51, 19, 59, 27,
                      34, 2, 42, 10, 50, 18, 58, 26,
                      33, 1, 41,  9, 49, 17, 57, 25,
            };
            int[] temp;
            switch (number)
            {
                case 0:
                    temp = new int[64];
                    for (int i = 0; i < 64; i++)
                            temp[i] = dataBlock[IP[i] - 1];
                    return temp;
                case 1:
                    temp = new int[56];
                    for (int i = 0; i < 56; i++)
                            temp[i] = dataBlock[PC1[i] - 1];
                    return temp;
                case 2:
                    temp = new int[48];
                    for (int i = 0; i < 48; i++)
                        temp[i] = dataBlock[PC2[i] - 1];
                    return temp;
                case 3:
                    temp = new int[48];
                    for (int i = 0; i < 48; i++)
                        temp[i] = dataBlock[EP[i] - 1];
                    return temp;
                case 4:
                    temp = new int[32];
                    for (int i = 0; i < 32; i++)
                        temp[i] = dataBlock[P[i] - 1];
                    return temp;
                case 5:
                    temp = new int[64];
                    for (int i = 0; i < 64; i++)
                        temp[i] = dataBlock[IPInverse[i] - 1];
                    return temp;
            }
            int[] garbage = new int[1];
            return garbage;

        }

        public int[] DataShifter(int[] dataBlock, int round)
        {
            int[] Shifted = new int[28];
            switch (round)
            {
                case 1:
                case 2:
                case 9:
                case 16:
                    for (int i = 0; i < 28; i++)
                        Shifted[i] = dataBlock[(i + 1) % 28];
                    break;
                default:
                    for (int i = 0; i < 28; i++)
                        Shifted[i] = dataBlock[(i + 2) % 28];
                    break;

            }
            return Shifted;

        }

        public int[] XOR(int[] first, int[] second)
        {
            int[] temp = new int[first.Length];
            for (int i = 0; i < first.Length; i++)
                if (first[i] == second[i])
                    temp[i] = 0;
                else
                    temp[i] = 1;
            return temp;
        }

        public int[] SBox(int[] datablock, Dictionary<string, int> binToNum, Dictionary<int, string> NumToBin)
        {
            int[] S1 =
            {
                          14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 ,
                           0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                           4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                          15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            };
            int[] S2 =
            {
                          15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                           3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 ,
                           0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                          13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            };
            int[] S3 =
            {
                       10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 ,
                       13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 ,
                       13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 ,
                        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            };
            int[] S4 =
            {
                        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 ,
                       13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 ,
                       10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 ,
                       3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            };
            int[] S5 =
            {
                         2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 ,
                       14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 ,
                       4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 ,
                       11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ,
            };
            int[] S6 =
            {
                         12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 ,
                       10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 ,
                       9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 ,
                       4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 ,
            };
            int[] S7 =
            {
                       4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 ,
                       13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 ,
                       1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 ,
                       6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ,
            };
            int[] S8 =
            {
                       13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 ,
                       1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 ,
                       7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 ,
                       2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
            };
            int[] temp = new int[32];
            int counter = 0;
            for (int i = 0; i < 8; i++)
            {
                string block = "";
                for (int j = 0; j < 6; j++)
                    block = block + datablock[i * 6 + j].ToString();
                string row = block[0].ToString() + block[5].ToString();
                string col = block.Substring(1, 4);
                int r = FromBinToNum(row, binToNum);
                int c = FromBinToNum(col, binToNum);
                string innerTemp = " ";
                switch (i)
                {
                    case 0:
                        innerTemp = FromNumToBin(S1[r * 16 + c], NumToBin);
                        break;
                    case 1:
                        innerTemp = FromNumToBin(S2[r * 16 + c], NumToBin);
                        break;
                    case 2:
                        innerTemp = FromNumToBin(S3[r * 16 + c], NumToBin);
                        break;
                    case 3:
                        innerTemp = FromNumToBin(S4[r * 16 + c], NumToBin);
                        break;
                    case 4:
                        innerTemp = FromNumToBin(S5[r * 16 + c], NumToBin);
                        break;
                    case 5:
                        innerTemp = FromNumToBin(S6[r * 16 + c], NumToBin);
                        break;
                    case 6:
                        innerTemp = FromNumToBin(S7[r * 16 + c], NumToBin);
                        break;
                    case 7:
                        innerTemp = FromNumToBin(S8[r * 16 + c], NumToBin);
                        break;
                }
                for (int k = 0; k < 4; k++)
                {
                    temp[counter] = int.Parse(innerTemp[k].ToString());
                    counter++;
                }
            }
            return temp;
        }

        public override string Encrypt(string plainText, string key)
        {
            plainText = plainText.Substring(2);
            key = key.Substring(2);
            Dictionary<char,string> HextoBin = new Dictionary<char, string>();
            Dictionary<string, char> BintoHex = new Dictionary<string, char>();
            Dictionary<string,int> BintoNum = new Dictionary<string, int>();
            Dictionary<int, string> NumtoBin = new Dictionary<int, string>();
            HextoBin = IntilizeHexToBin(HextoBin);
            BintoHex = IntilizeBinToHex(BintoHex);
            BintoNum = IntilizeBinToNum(BintoNum);
            NumtoBin = IntilizeNumToBin(NumtoBin);
            int[] plainData = new int[64];
            int[] keyData = new int[64];
            int[] L = new int[32];
            int[] R = new int[32];
            int[] c = new int[28];
            int[] d = new int[28];
            // convert plain text and key to binary
            int counter = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                string temp = HextoBin[plainText[i]];
                for (int j = 0; j < 4; j++)
                {
                    plainData[counter] = int.Parse(temp[j] + " ");
                    counter++;
                }
            }
            counter = 0;
            for (int i = 0; i < key.Length; i++)
            {
                string temp = HextoBin[key[i]];
                for (int j = 0; j < 4; j++)
                {
                    keyData[counter] = int.Parse(temp[j] + " ");
                    counter++;
                }
            }

            // apply IP to key

            keyData = Permutation(keyData, 1);
            // split key into c and d
            for (int i = 0; i < 28; i++)
            {
                c[i] = keyData[i];
                d[i] = keyData[i + 28];
            }
            // apply IP to plain text
            plainData = Permutation(plainData, 0);
            // split plain text into L and R
            for (int i = 0; i < 32; i++)
            {
                L[i] = plainData[i];
                R[i] = plainData[i + 32];
            }
            // apply 16 rounds
            for(int round = 1; round <= 16; round++)
            {
                int[] tempKey = new int[56];
                c = DataShifter(c, round);
                d = DataShifter(d, round);
                for (int i = 0; i < 28; i++)
                {
                    tempKey[i] = c[i];
                    tempKey[i+28] = d[i];
                }
                tempKey = Permutation(tempKey, 2);
                int[] RHolder = R;
                R = Permutation(R, 3);
                int[] XORed = new int[48];
                XORed = XOR(R, tempKey);
                XORed = SBox(XORed, BintoNum, NumtoBin);
                XORed = Permutation(XORed, 4);
                int[] result = XOR(XORed, L);
                L = RHolder;
                R = result;

            }
            // apply final permutation
            for (int i = 0; i < 32; i++)
            {
                plainData[i] = R[i];
                plainData[i+32] = L[i];
            }
            plainData = Permutation(plainData, 5);
            string cipher = "0x";
            for (int i = 0;i < 16; i++)
            {
                string temp = "";
                for (int j = 0; j < 4; j++)
                {
                    temp = temp + plainData[i * 4 + j];
                }
                cipher += FromBinToHex(temp,BintoHex);
            }
            return cipher;
        }

        public override string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.Substring(2);
            key = key.Substring(2);
            Dictionary<char, string> HextoBin = new Dictionary<char, string>();
            Dictionary<string, char> BintoHex = new Dictionary<string, char>();
            Dictionary<string, int> BintoNum = new Dictionary<string, int>();
            Dictionary<int, string> NumtoBin = new Dictionary<int, string>();
            HextoBin = IntilizeHexToBin(HextoBin);
            BintoHex = IntilizeBinToHex(BintoHex);
            BintoNum = IntilizeBinToNum(BintoNum);
            NumtoBin = IntilizeNumToBin(NumtoBin);
            int[] cipherData = new int[64];
            int[] keyData = new int[64];
            int[] L = new int[32];
            int[] R = new int[32];
            int[] c = new int[28];
            int[] d = new int[28];
            List<int[]> keys = new List<int[]>();
            // convert cipher text and key to binary
            int counter = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                string temp = HextoBin[cipherText[i]];
                for (int j = 0; j < 4; j++)
                {
                    cipherData[counter] = int.Parse(temp[j] + " ");
                    counter++;
                }
            }
            counter = 0;
            for (int i = 0; i < key.Length; i++)
            {
                string temp = HextoBin[key[i]];
                for (int j = 0; j < 4; j++)
                {
                    keyData[counter] = int.Parse(temp[j] + " ");
                    counter++;
                }
            }
            //apply IP to key 
            keyData = Permutation(keyData, 1);
            // split key into c and d
            for (int i = 0; i < 28; i++)
            {
                c[i] = keyData[i];
                d[i] = keyData[i + 28];
            }
            // apply IP to cipher text
            cipherData = Permutation(cipherData, 0);
            // split cipher text into L and R
            for (int i = 0; i < 32; i++)
            {
                L[i] = cipherData[i];
                R[i] = cipherData[i + 32];
            }
            // apply 16 rounds
            for (int round = 1; round <= 16; round++)
            {
                int[] tempKey = new int[56];
                c = DataShifter(c, round);
                d = DataShifter(d, round);
                for (int i = 0; i < 28; i++)
                {
                    tempKey[i] = c[i];
                    tempKey[i + 28] = d[i];
                }
                tempKey = Permutation(tempKey, 2);
                keys.Add(tempKey);
            }
            for (int round = 15; round >= 0; round--)
            {
                int[] RHolder = R;
                R = Permutation(R, 3);
                int[] XORed = new int[48];
                XORed = XOR(R, keys[round]);
                XORed = SBox(XORed, BintoNum, NumtoBin);
                XORed = Permutation(XORed, 4);
                int[] result = XOR(XORed, L);
                L = RHolder;
                R = result;
            }
                
            // apply final permutation
            for (int i = 0; i < 32; i++)
            {
                cipherData[i] = R[i];
                cipherData[i + 32] = L[i];
            }
            cipherData = Permutation(cipherData, 5);
            string plain = "0x";
            for (int i = 0; i < 16; i++)
            {
                string temp = "";
                for (int j = 0; j < 4; j++)
                {
                    temp = temp + cipherData[i * 4 + j];
                }
                plain += FromBinToHex(temp, BintoHex);
            }
            return plain;

        }
    }
}