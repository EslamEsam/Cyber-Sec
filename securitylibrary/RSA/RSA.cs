using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int getMod(int a, int b, int n)
        {
            long ans = 1, tempM = a;
            while (b > 0)
            {
                if (b % 2 == 1)
                {
                    ans = (ans * tempM) % n;
                }
                tempM = (tempM * tempM) % n;
                b /= 2;
            }
            return (int)(ans % n);
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int euler = (p - 1) * (q - 1);
            int ans = getMod(M, e, n);
            return ans % n;

        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int euler = (p - 1) * (q - 1);
            ExtendedEuclid ee = new ExtendedEuclid();
            int d = ee.GetMultiplicativeInverse(e, euler);
            int ans = getMod(C, d, n);
            return ans % n;
        }
    }
}
