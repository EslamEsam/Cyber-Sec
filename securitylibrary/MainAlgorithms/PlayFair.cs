using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        int mod(int x, int m) =>
            (x % m + m) % m;
        
        char[,] generateKeyTable(string key)
        {
            key = new HashSet<char>(key.ToLower().Replace("J", "I"))
                    .Aggregate("", (acc, c) => acc + c);


            char[,] table = new char[5, 5];
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            alphabet = alphabet.ToLower();
            int k = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (k < key.Length)
                    {
                        table[i, j] = key[k];
                        alphabet = alphabet.Replace(key[k].ToString(), "");
                        k++;
                    }
                    else
                    {
                        table[i, j] = alphabet[0];
                        alphabet = alphabet.Substring(1);
                    }
                }
            }
            return table;
        }

        string seperateConsecutiveChars(string text)
        {
            string pairs = "";
            for (int i = 0; i < text.Length; i += 2)
            {
                char c1 = text[i];
                char c2 = (i + 1 < text.Length) ? text[i + 1] : 'X';
                if (c1 == c2)
                {
                    c2 = 'X';
                    i--;
                }
                pairs += $"{c1}{c2}";
            }


            return pairs;
        }

        int[] indexOf(char[,] table, char c)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (table[i, j] == c)
                        return new int[] { i, j };
                }
            }

            // Not found
            return new int[] { -1, -1 };
        }

        string preprocessEnc(string text)
        {
            // Seperate consecutive chars with an X (if they are the same)
            // - J's are replaced with I's
            // - Spaces are removed

            text = seperateConsecutiveChars(text)
                    .ToLower()
                    .Replace("J", "I")
                    .Replace(" ", "");

            // - If the length of the text is odd, add an X at the end
            if (text.Length % 2 != 0)
                text += "X";

            return text;
        }

        string postprocessDec(string text)
        {
            for (int i = 1; i < text.Length - 1; i += 2)
            {
                if (text[i] == 'x' && text[i + 1] == text[i - 1])
                {
                    text = text.Remove(i, 1);
                    text = text.Insert(i, ".");
                }
            }
            text = text.Replace(".", "");

            if (text[text.Length - 1] == 'x')
            {
                text = text.Remove(text.Length - 1);
            }
            return text;
        }

        public string Decrypt(string cipherText, string key)
        {
            key = key.ToLower();
            cipherText = cipherText.ToLower();
            
            var table = generateKeyTable(key);

            var plainText = "";

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char c1 = cipherText[i];
                char c2 = cipherText[i + 1];

                int[] idx1 = indexOf(table, c1);
                int[] idx2 = indexOf(table, c2);

                /* 
                    * 1. Same row: idx1[0] = idx2[0] => Move left (circular)
                    * 2. Same column idx1[1] = idx2[1] => Move up (circular)
                    * 3. Different row/col => rectangular
                */

                if (idx1[0] == idx2[0])
                {
                    plainText += table[idx1[0], mod((idx1[1] - 1), 5)];
                    plainText += table[idx2[0], mod((idx2[1] - 1), 5)];
                }
                else if (idx1[1] == idx2[1])
                {
                    plainText += table[mod((idx1[0] - 1), 5), idx1[1]];
                    plainText += table[mod((idx2[0] - 1), 5), idx2[1]];
                }
                else
                {
                    plainText += table[idx1[0], idx2[1]];
                    plainText += table[idx2[0], idx1[1]];
                }
            }

            // Clean all unnecessary X's
            plainText = postprocessDec(plainText);
            
            return plainText;

        }

        public string Encrypt(string plainText, string key)
        {
            var table = generateKeyTable(key);

            plainText = preprocessEnc(plainText);

            var cipherText = "";


            for (int i = 0; i < plainText.Length; i += 2)
            {
                char c1 = plainText[i];
                char c2 = plainText[i + 1];

                int[] idx1 = indexOf(table, c1);
                int[] idx2 = indexOf(table, c2);

                /* 
                    * 1. Same row: idx1[0] = idx2[0] => Move right (circular)
                    * 2. Same column idx1[1] = idx2[1] => Move down (circular)
                    * 3. Different row/col => rectangular
                */

                if (idx1[0] == idx2[0])
                {
                    cipherText += table[idx1[0], (idx1[1] + 1) % 5];
                    cipherText += table[idx2[0], (idx2[1] + 1) % 5];
                }
                else if (idx1[1] == idx2[1])
                {
                    cipherText += table[(idx1[0] + 1) % 5, idx1[1]];
                    cipherText += table[(idx2[0] + 1) % 5, idx2[1]];
                }
                else
                {
                    cipherText += table[idx1[0], idx2[1]];
                    cipherText += table[idx2[0], idx1[1]];
                }
            }

            return cipherText;
        }
    }
}