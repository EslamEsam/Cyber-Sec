using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        int Power_Mod(int actualNum, int powered, int qq)
        {
            int ans = 1;
            for (int i = 0; i < powered; i++)
            {
                ans = (actualNum * ans) % qq;
            }

            return ans;
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {

            int kC = Power_Mod(y, k, q);

            long c1 = Power_Mod(alpha, k, q);

            long c2 = (m * kC) % q;

            List<long> cipherr = new List<long>();

            cipherr.Add(c1);
            cipherr.Add(c2);

            return cipherr;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int kC = Power_Mod(c1, x, q);
            int k_inverse = new ExtendedEuclid().GetMultiplicativeInverse(kC, q); ; 
            //for(int i =1;i<= q; i++)
            //{
            //    if (((kC * i) % q) == 1)
            //    {
            //        k_inverse = i;
            //        break;
            //    }
            //}
            int message = (c2 * k_inverse) % q;

            return message;
        }
    }
}
