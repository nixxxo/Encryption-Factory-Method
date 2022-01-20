using System;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;


namespace JPL_Internship
{
    class Program
    {
        static void Main(string[] args)
        {
            // * Getting the user data

            // Console.Write("Please specify data path: ");
            // String filePath = Console.ReadLine();
            string filePath = "test.json";

            dynamic userInput = JsonConvert.DeserializeObject(File.ReadAllText($@"{filePath}"));

            string userInfo = userInput.info;

            // Console.WriteLine(userInfo);

            // * Creating the hash

            StringBuilder stringBdr = new StringBuilder(); // repeated modifications to a string

            byte[] textBytes = Encoding.ASCII.GetBytes(userInfo); // converting string to into a bytes array

            using (SHA1 encr = SHA1.Create())
            {
                byte[] generateHash = encr.ComputeHash(textBytes);

                for (int i = 0; i<generateHash.Length; i++)
                {
                    stringBdr.Append(generateHash[i].ToString("x2")); // hexadecimal string conversion
                }
            }

            // * Storing user data in JSON

            var myDict = new Dictionary<string, string>();
            myDict.Add("type", "1" ); // ? question - what should I do here?
            myDict.Add("hash", $"{stringBdr}" );
            myDict.Add("data", $"{userInfo}");

            string json = JsonConvert.SerializeObject( myDict );

            Console.WriteLine(json);

            File.WriteAllText(@"encryption.json", json);

        }

    }
}
