using SecurityLibrary.AES;
using SecurityLibrary.ElGamal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Power_Mod(int actualNum, int powered, int qq)
        {
            int ans = 1;
            for (int i = 0; i < powered; i++)
            {
                ans = (actualNum * ans) % qq;
            }

            return ans;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int euler = (p - 1) * (q - 1);
            int ans =  Power_Mod(M, e, n);
            return ans % n;

        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int euler = (p - 1) * (q - 1);
            ExtendedEuclid ee = new ExtendedEuclid();
            int d = ee.GetMultiplicativeInverse(e, euler);
            int ans = Power_Mod(C, d, n);
            return ans % n;
        }
    }
}
