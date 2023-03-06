using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int cnt = 0;

            for (int i = 0; i < cipherText.Length; i ++)
            {
                cipherText = cipherText.ToLower ();
                if (cipherText[1]!= plainText[i]|| cipherText[1] == plainText[i+1])
                {
                    cnt++;
                }
               else if (cipherText[1] == plainText[i])
                {
                    break;
                }

            }
            System.Console.WriteLine(cnt);

            return cnt;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plain = "";
            StringBuilder cipher = new StringBuilder(cipherText);
            
            int length = (int)Math.Ceiling((decimal)(cipherText.Length)/ (decimal)key);
            for (int i = 0; i <cipherText.Length; i ++)
            {
                if (cipher[i] != '#')
                {
                    plain += cipher[i];
                }
                int idx = i + length;
                for (int j = 0; j < key - 1; j++)
                {
                    
                    if (idx< cipherText.Length && cipher[idx] != '#')
                    {
                        plain += cipher[idx];
                        cipher[idx] = '#';
                        idx+= length;
                    }
                }
                
            }
            return plain;
        }

        public string Encrypt(string plainText, int key)
        {
            string cipher = "";
            for (int i = 0; i < plainText.Length; i+= key)
            {
               
                cipher += plainText[i];
                
           }
            for (int j = 0; j < key - 1; j++)
            {

                for (int i = 1+j; i < plainText.Length; i += key)
                {

                    cipher += plainText[i];

                }
            }
            return cipher;
        }
    }
}
