using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int[] A = {1,0, baseN };
            int[] B = { 0, 1, number };
            int[] temp =new int [3];
            int division;

            while (true) {
                if (B[2] == 0)
                {
                    return-1;
                }

                else if (B[2] == 1)
                {
                    return (B[1] + baseN) % baseN;
                }

                 division =  A[2] / B[2];

                for (int i = 0; i < 3; i++)
                {
                    temp[i] = A[i] - (division * B[i]);
                }

                for (int i = 0; i < 3; i++)
                {
                    A[i] = B[i];
                    B[i] = temp[i];
                }
            }


        }
    }
}