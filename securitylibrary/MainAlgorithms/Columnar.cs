using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {

            List<int> keys = new List<int>();
            List<List<int>> allkeys = new List<List<int>>();

            for (int i = 2; i <= 10; i++)
            {
                int lenght = i;
                int[] eyarr = new int[lenght];
                for (int j = 1; j <= lenght; j++)
                {
                    eyarr[j - 1] = j;
                }
                P(eyarr, 0);

            }

            void P(int[] keyarr, int i)
            {
                if (i == keyarr.Length - 1)
                {

                    List<int> lst = keyarr.ToList();
                    allkeys.Add(lst);
                    return;
                }

                for (int j = i; j < keyarr.Length; j++)
                {
                    S(keyarr, i, j);
                    P(keyarr, i + 1);
                    S(keyarr, i, j);
                }

            }
            void S(int[] swaparr, int i, int j)
            {
                int t = swaparr[i];
                swaparr[i] = swaparr[j];
                swaparr[j] = t;
            }
            for (int i = 0; i < allkeys.Count; i++)
            {
                string ans = Encrypt(plainText, allkeys[i]);
                if (ans.ToUpper() == cipherText.ToUpper())
                {
                    return allkeys[i];
                }
            }

            return keys;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int r, c;
            string plainText = "";
            c = key.Count;

            r = cipherText.Length / c;

            int cnt = 0;
            char[,] myMatrix = new char[r, c];
            char[,] Matrix = new char[r, c];
            for (int cc = 0; cc < c; cc++)
            {
                for (int rr = 0; rr < r; rr++)
                {
                    myMatrix[rr, cc] = cipherText[cnt];
                    cnt++;
                }
            }

            for (int l = 0; l < c; l++)
            {
                int j = key[l] - 1;
                for (int i = 0; i < r; i++)
                {
                    Matrix[i, l] = myMatrix[i, j];
                }
            }
            for (int i = 0; i < r; i++)
            {
                for (int j = 0; j < c; j++)
                {
                    if (Matrix[i, j] != 'x')
                        plainText += Matrix[i, j];
                }
            }

            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int r, c;
            string cipherText = "";
            c = key.Count;
            r = plainText.Length / c;
            if (plainText.Length % c != 0)
                r += 1;
            Dictionary<int, int> keymap = new Dictionary<int, int>();

            int cnt = 0;
            char[,] myMatrix = new char[r, c];
            for (int rr = 0; rr < r; rr++)
            {
                for (int cc = 0; cc < c; cc++)
                {
                    if (cnt >= plainText.Length)
                        myMatrix[rr, cc] = 'x';
                    else
                        myMatrix[rr, cc] = plainText[cnt];

                    cnt++;
                }
            }

            int roww = 0;
            for (int i = 1; i <= key.Count; i++)
            {
                roww = 0;
                for (int j = 0; j < key.Count; j++)
                {
                    if (key[j] == i)
                    {
                        for (int k = 0; k < r; k++)
                        {
                            if (myMatrix[k, j] != 'x')
                            {
                                cipherText += myMatrix[k, j];
                            }

                        }
                        break;
                    }


                }
            }


            return cipherText;
        }
    }
}
