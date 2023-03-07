using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string output = "";
            int indx;
            plainText = plainText.ToUpper();
            for (int i = 0; i < plainText.Length; i++)
            {
                int x = plainText[i];
                indx = plainText[i] - 65;
                indx = indx + key;
                if (indx > 25)
                {
                    indx = indx % 26;
                }
                indx = indx + 65;
                output += ((char)indx).ToString();
            }
            return output.ToUpper();

        }

        public string Decrypt(string cipherText, int key)
        {
            string output = "";
            int indx;
            cipherText = cipherText.ToUpper();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int x = cipherText[i];
                indx = cipherText[i] - 65;
                indx = indx - key;
                while (indx < 0)
                {
                    indx = indx + 26;
                }
                indx = indx + 65;
                output += ((char)indx).ToString();
            }
            return output.ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            int output;
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            output = cipherText[0] - plainText[0];
            if (output < 0)
            {
                output += 26;
            }
            return output;
        }
    }
}