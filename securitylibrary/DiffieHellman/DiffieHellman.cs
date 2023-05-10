using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        int Power_Mod(int actualNum, int powered, int qq)
        {
            int ans = 1;
            for (int i = 0; i < powered; i++)
            {
                ans = (actualNum * ans) % qq;
            }

            return ans;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = Power_Mod(alpha, xa, q);
            int yb = Power_Mod(alpha, xb, q);
            int ans1 = Power_Mod(yb, xa, q);
            int ans2 = Power_Mod(ya, xb, q);
            return new List<int>() { ans1, ans2 };
        }
    }
}