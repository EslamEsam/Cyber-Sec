using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        // helper functions
        List<char> alphabet = new List<char>
        {
                 'a', 'b', 'c', 'd', 'e', 'f',
                 'g', 'h', 'i','j', 'k', 'l', 'm',
                 'n', 'o', 'p', 'q', 'r','s',
                 't', 'u', 'v', 'w', 'x','y', 'z'
        };

        private List<int> stringToList(string plainText)
        {
            List<int> plainList = new List<int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                plainList.Add(alphabet.IndexOf(plainText[i]));
            }
            return plainList;
        }

        private string listToString(List<int> plainText)
        {
            string plainString = "";
            for (int i = 0; i < plainText.Count; i++)
            {
                plainString += alphabet[plainText[i]];
            }
            return plainString;
        }

        private int GCD(int firstNum , int secondNum)
        {
            if (secondNum == 0)
                return firstNum;
            else
                return GCD(secondNum, firstNum % secondNum);
        }

        //this method determines the sign of the elements
        private int SignOfElement(int i, int j)
        {
            if ((i + j) % 2 == 0)
            {
                return 1;
            }
            else
            {
                return -1;
            }
        }
        //this method determines the sub matrix corresponding to a given element
        private int[,] CreateSmallerMatrix(int[,] input, int i, int j)
        {
            int order = int.Parse(System.Math.Sqrt(input.Length).ToString());
            int[,] output = new int[order - 1, order - 1];
            int x = 0, y = 0;
            for (int m = 0; m < order; m++, x++)
            {
                if (m != i)
                {
                    y = 0;
                    for (int n = 0; n < order; n++)
                    {
                        if (n != j)
                        {
                            output[x, y] = input[m, n];
                            y++;
                        }
                    }
                }
                else
                {
                    x--;
                }
            }
            return output;
        }
        //this method determines the value of determinant using recursion
        private int Determinant(int[,] input)
        {
            int order = int.Parse(System.Math.Sqrt(input.Length).ToString());
            if (order > 2)
            {
                int value = 0;
                for (int j = 0; j < order; j++)
                {
                    int[,] Temp = CreateSmallerMatrix(input, 0, j);
                    value = value + input[0, j] * (SignOfElement(0, j) * Determinant(Temp));
                }
                return value;
            }
            else if (order == 2)
            {
                return ((input[0, 0] * input[1, 1]) - (input[1, 0] * input[0, 1]));
            }
            else
            {
                return (input[0, 0]);
            }
        }

        private int[,] listToMatrix (List<int> list)
        {
            int[,] matrix;
            int counter = 0;
            if (list.Count % 2 == 0)
            {
                matrix = new int[2, 2];
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        matrix[i, j] = list[counter];
                        counter++;
                    }
                }
            }
            else
            {
                matrix = new int[3, 3];
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        matrix[i, j] = list[counter];
                        counter++;
                    }
                }
            }
            
            return matrix;
        }
        
        private List<int> MatrixToList(int[,] matrix)
        {
            List<int> list = new List<int>();
            for (int i = 0; i <  matrix.GetLength(0); i++)
            {
                for (int j = 0;j < matrix.GetLength(1); j++)
                {
                    list.Add(matrix[i, j]);
                }
            }
            return list;
        }

        private int mod (int num1 , int num2)
        {
            if (num1 < 0)
                return ((num1 % num2) + num2) % num2;
            else
                return num1 % num2;
        }

        private int calculateB (int det)
        {
            int result = 0;
            for (int i = 2; i < 26; i++)
            {
                if (((i * det) % 26) == 1)
                {
                    result = i;
                    break;
                }
            }
            return result;
        }

        private int[,] flip2x2Matrix(int[,] matrix)
        {
            int[,] flipMatrix = new int[2, 2];
            flipMatrix[0, 0] = matrix[1, 1];
            flipMatrix[1, 1] = matrix[0, 0];
            flipMatrix[0, 1] = -matrix[0, 1];
            flipMatrix[1, 0] = -matrix[1, 0];
            return flipMatrix;
        }

        private int[,] subMatrix(int[,] matrix , int row ,int column)
        {
            int[,] subMatrix = new int[matrix.GetLength(0) - 1 , matrix.GetLength(1) - 1];
            int newRow = 0 , newColumn = 0 ;
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                if (i == row)
                    continue;
                newColumn = 0;
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    if (j == column)
                        continue;
                    subMatrix[newRow,newColumn] = matrix[i,j];
                    newColumn++;
                }
                newRow++;
            }
            return subMatrix;
        }

        private int[,] matrixTranspose(int[,] matrix)
        {
            int[,] transposedMatrix = new int[matrix.GetLength(0), matrix.GetLength(1)];
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    transposedMatrix[j,i] = matrix[i,j];
                }
            }
            return transposedMatrix;
        }

        private int[,] MultiplyMatrix(int[,] matA, int[,] matB)
        {
            int rowACount = matA.GetLength(0);
            int colACount = matA.GetLength(1);
            int rowBCount = matB.GetLength(0);
            int colBCount = matB.GetLength(1);

            if (colACount != rowBCount)
            {
                return null;
            }
            else
            {
                int temp = 0;
                int[,] res = new int[rowACount, colBCount];

                for (int i = 0; i < rowACount; i++)
                {
                    for (int j = 0; j < colBCount; j++)
                    {
                        temp = 0;
                        for (int k = 0; k < colACount; k++)
                        {
                            temp += matA[i, k] * matB[k, j];
                        }
                        res[i, j] = temp;
                    }
                }

                return res;
            }
        }

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();
            bool flag = false;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {   
                            List<int> tempKey = new List<int> {i,j,k,l }; 
                            key = Encrypt(plainText,tempKey);
                            flag = Enumerable.SequenceEqual(key, cipherText);
                            if (flag)
                                return tempKey;
                        }
                    }
                }
            }
            if (!flag)
                throw new InvalidAnlysisException();
            else 
                return key;
        }

        public string Analyse(string plainText, string cipherText)
        {

            List<int> plainList = stringToList(plainText);
            List<int> cipherList = stringToList(cipherText);
            
            List<int> keyList = Analyse(plainList, cipherList);

            return listToString(keyList);
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainTextList = new List<int>();
            int[,] keyMatrix = listToMatrix(key);
            if (keyMatrix.GetLength(0) != keyMatrix.GetLength(1))
                throw new InvalidAnlysisException(); 
            List<int> keyInverseList = new List<int>();
            int[,] keyInverseMatrix = new int[keyMatrix.GetLength(0), keyMatrix.GetLength(1)];
            if (keyMatrix.GetLength(0) == 2)
            {
                int det = Determinant(keyMatrix);
                int[,] flippedMatrix = flip2x2Matrix(keyMatrix);
                for (int i = 0;i < keyMatrix.GetLength(0); i++)
                {
                    for (int j = 0;j < keyMatrix.GetLength(1); j++)
                    {
                        keyInverseMatrix[i, j] = mod(((1 / det) * flippedMatrix[i, j]), 26);
                    }
                }
                keyInverseList = MatrixToList(keyInverseMatrix);
                for (int i = 0; i < cipherText.Count; i += 2)
                {
                    for ( int j = 0;j < keyInverseList.Count; j += 2)
                    {
                        plainTextList.Add(((keyInverseList[j] * cipherText[i]) + (keyInverseList[j + 1] * cipherText[i + 1])) % 26);
                    }
                }
            }
            if (keyMatrix.GetLength(0) == 3)
            {
                int det = mod(Determinant(keyMatrix), 26);
                int b = calculateB(det);
                for (int i = 0; i <  keyMatrix.GetLength(0); i++)
                {
                    for (int j = 0; j < keyMatrix.GetLength(1); j++)
                    {
                        int[,] subMat = subMatrix(keyMatrix, i, j);
                        int subDet = mod(Determinant(subMat), 26);
                        keyInverseMatrix[i, j] = mod(Convert.ToInt32(b * Math.Pow(-1,i+j) * subDet),26);
                    }
                }
                keyInverseMatrix = matrixTranspose(keyInverseMatrix);
                keyInverseList = MatrixToList(keyInverseMatrix);
                for (int i = 0; i < cipherText.Count; i+=3)
                {
                    for(int j = 0;j < keyInverseList.Count; j += 3)
                    {
                        plainTextList.Add(((keyInverseList[j] * cipherText[i])+(keyInverseList[j+1] * cipherText[i+1]) +(keyInverseList[j+2] * cipherText[i+2])) % 26);
                    }
                }
            }
            int counter = 0;
            for (int i = 0;i < plainTextList.Count; i++)
            {
                if (plainTextList[i] == 0)
                    counter++;
            }
            if (counter == plainTextList.Count)
                throw new InvalidAnlysisException(); 
            else
                return plainTextList;

        }

        public string Decrypt(string cipherText, string key)
        {
            List<int> cipherList = stringToList(cipherText);
            List<int> keyList = stringToList(key);

            List<int> plainList = Decrypt(cipherList, keyList);

            return listToString(plainList);
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {

            List<int> cipherList = new List<int>();
            if (key.Count % 2 == 0)
            {
                for (int i = 0; i < plainText.Count; i+=2)
                {
                    for (int j = 0; j < key.Count; j +=2)
                    {
                        cipherList.Add(((key[j] * plainText[i]) + (key[j + 1] * plainText[i + 1])) % 26);
                    }
                }
            }
            else if (key.Count % 3 == 0)
            {
                for (int i = 0; i < plainText.Count; i +=3)
                {
                    for (int j = 0; j < key.Count; j+=3)
                    {
                        cipherList.Add(((key[j] * plainText[i]) + (key[j + 1] * plainText[i + 1]) + (key[j + 2] * plainText[i + 2])) % 26);
                    }
                }
            }
            return cipherList;
        }

        public string Encrypt(string plainText, string key)
        {
            List<int> plainTextList = stringToList(plainText);
            List<int> keyList = stringToList(key);

            List<int> cipherList = Encrypt(plainTextList, keyList);

            return listToString(cipherList);

        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int[,] plainMatrix = listToMatrix(plain3);
            int[,] plainInverseMatrix = new int[3, 3];
            List<int> plainInverseList = new List<int>();
            List<int> keyList = new List<int>();
            int det = Determinant(plainMatrix);
            int b = calculateB(det);
            if (det == 0 || GCD(26, det) != 1 || b == 0)
                throw new InvalidAnlysisException();
            for (int i = 0; i < plainMatrix.GetLength(0); i++)
            {
                for (int j = 0; j < plainMatrix.GetLength(1); j++)
                {
                    int[,] subMat = subMatrix(plainMatrix, i, j);
                    int subDet = mod(Determinant(subMat), 26);
                    plainInverseMatrix[i, j] = mod(Convert.ToInt32(b * Math.Pow(-1, i + j) * subDet), 26);
                }
            }

            int[,] cipherMatrix = matrixTranspose(listToMatrix(cipher3));
            int[,] keyMatrix = MultiplyMatrix(cipherMatrix, plainInverseMatrix);
            
            for (int i = 0; i < keyMatrix.GetLength(0); i++)
            {
                for (int j = 0; j <  keyMatrix.GetLength(1); j++)
                {
                    keyMatrix[i, j] = mod(keyMatrix[i, j], 26);
                }
            }
            keyList = MatrixToList(keyMatrix);

            return keyList;

        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            List<int> plainList = stringToList(plain3);
            List<int> cipherList = stringToList(cipher3);

            List<int> keyList = Analyse3By3Key(plainList, cipherList);

            return listToString(keyList);
        }
    }
}
