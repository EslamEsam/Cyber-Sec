using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string output = "";
            int indx, x = 33;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < 26; i++)
            {
                indx = i + 97;

                indx = plainText.IndexOf((char)indx);
                if (indx == -1)
                {
                    output += ((char)x).ToString();
                    x++;
                    continue;
                }
                output += cipherText[indx];
            }
            return output.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            string output = "";
            int indx;
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                indx = key.IndexOf(cipherText[i]);
                indx += 65;
                output += ((char)indx).ToString();
            }
            return output.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            string output = "";
            int indx;
            plainText = plainText.ToLower();
            key = key.ToLower();
            for (int i = 0; i < plainText.Length; i++)
            {
                indx = plainText[i] - 97;
                output += key[indx];
            }
            return output.ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51% .
        /// T	9.25 .
        /// A	8.04 .
        /// O	7.60 .
        /// I	7.26 .
        /// N	7.09 .
        /// S	6.54 .
        /// R	6.12 .
        /// H	5.49 .
        /// L	4.14 .
        /// D	3.99 .
        /// C	3.06 .
        /// U	2.71 .
        /// M	2.53 .
        /// F	2.30 .
        /// P	2.00 .
        /// G	1.96 .
        /// W	1.92 .
        /// Y	1.73 .
        /// B	1.54 .
        /// V	0.99 .
        /// K	0.67 .
        /// X	0.19 .
        /// J	0.16 .
        /// Q	0.11 .
        /// Z	0.09 .
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string output = "..........................";
            StringBuilder str = new StringBuilder(output);
            SortedList<char, float> L = new SortedList<char, float>();
            cipher = cipher.ToLower();
            float indx, freq;
            char x;
            for (int i = 0; i < 26; i++)
            {
                indx = i + 97;
                x = ((char)indx);
                freq = cipher.Count(f => (f == x));
                freq = freq / cipher.Length;
                L.Add(x, freq);
            }
            var orderByVal = L.OrderBy(kvp => kvp.Value);
            var dec = orderByVal.Reverse();
            str[4] = dec.ElementAt(0).Key;
            str[19] = dec.ElementAt(1).Key;
            str[0] = dec.ElementAt(2).Key;
            str[14] = dec.ElementAt(3).Key;
            str[8] = dec.ElementAt(4).Key;
            str[13] = dec.ElementAt(5).Key;
            str[18] = dec.ElementAt(6).Key;
            str[17] = dec.ElementAt(7).Key;
            str[7] = dec.ElementAt(8).Key;
            str[11] = dec.ElementAt(9).Key;
            str[3] = dec.ElementAt(10).Key;
            str[2] = dec.ElementAt(11).Key;
            str[20] = dec.ElementAt(12).Key;
            str[12] = dec.ElementAt(13).Key;
            str[5] = dec.ElementAt(14).Key;
            str[15] = dec.ElementAt(15).Key;
            str[6] = dec.ElementAt(16).Key;
            str[22] = dec.ElementAt(17).Key;
            str[24] = dec.ElementAt(18).Key;
            str[1] = dec.ElementAt(19).Key;
            str[21] = dec.ElementAt(20).Key;
            str[10] = dec.ElementAt(21).Key;
            str[23] = dec.ElementAt(22).Key;
            str[9] = dec.ElementAt(23).Key;
            str[16] = dec.ElementAt(24).Key;
            str[25] = dec.ElementAt(25).Key;

            output = str.ToString();
            Monoalphabetic algorithm = new Monoalphabetic();
            output = algorithm.Decrypt(cipher, output);

            return output.ToLower();
        }

    }
}