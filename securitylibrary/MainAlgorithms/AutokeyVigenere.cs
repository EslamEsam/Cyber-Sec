using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string autoKey(string key, string plainText)
        {
            int diff = plainText.Length - key.Length;
            int c = diff / plainText.Length;
            diff = diff % plainText.Length;
            for (int i = 0; i < c; i++)
            {
                key = key + plainText;
            }
            key = key + plainText.Substring(0, diff);
            return key;
        }
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            string key = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int k = (cipherText[i] - plainText[i] + 26) % 26;
                k += 'A';
                key += (char)k;
            }
            int index;
            for (int i = 1; i < key.Length; i++)
            {
                if (key[i] == plainText[0])
                {
                    index = i;
                    int k0 = 1, ki = i + 1;
                    while (ki < key.Length - 1 && key[ki] == plainText[k0])
                    {
                        k0++;
                        ki++;
                    }
                    if (ki >= key.Length - 1)
                    {
                        key = key.Substring(0, i);
                        return key;
                    }
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string plain = "";
            int j = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (i >= key.Length)
                {
                    key = key + plain[j];
                    j = j + 1;
                }
                int decrypted = (cipherText[i] - key[i] + 26) % 26;
                decrypted += 'A';
                plain += (char)decrypted;
            }
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            if (key.Length < plainText.Length)
            {
                key = autoKey(key, plainText);
            }
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            string cipher = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int encrypted = (plainText[i] + key[i]) % 26;
                encrypted += 'A';
                cipher += (char)encrypted;
            }
            return cipher;
        }
    }

}
