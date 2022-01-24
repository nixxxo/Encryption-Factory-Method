using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System.Security.Cryptography;


namespace JPL_Internship
{   
    public class EncryptionJson
    {
        public string Type { get; set; }
        public SymmetricAlgorithm Hash { get; set; }
        public string PrivateKey { get; set; }
        public byte[] Data { get; set; }
    }
    class Program
    {
        static string GenerateHash(string info)
        {
            StringBuilder stringBdr = new StringBuilder(); // repeated modifications to a string

            byte[] textBytes = Encoding.ASCII.GetBytes(info); // converting string to into a bytes array

            using (SHA1 encr = SHA1.Create())
            {
                byte[] generateHash = encr.ComputeHash(textBytes);

                for (int i = 0; i<generateHash.Length; i++)
                {
                    stringBdr.Append(generateHash[i].ToString("x2")); // hexadecimal string conversion
                }

                return stringBdr.ToString();
            }

        }
        static string FileToString (string path)
        {   
            StreamReader r = new StreamReader(path);
            string jsonString = r.ReadToEnd();

            return jsonString;
        }

        static EncryptionJson LoadJson(string path)
        {
            string file = FileToString(path);
            EncryptionJson json = Newtonsoft.Json.JsonConvert.DeserializeObject<EncryptionJson>(file);
            return json;
        }

        static void EncodedJsonSym(SymmetricAlgorithm hash, byte[] data, string fileName)
        {
            EncryptionJson json = new EncryptionJson();
            json.Type = "1";
            json.Hash = hash;
            json.Data = data;
            string jsonReady = JsonSerializer.Serialize(json);
            File.WriteAllText(@$"{fileName}", jsonReady);
        }
        static void EncodedJsonAsym(string hash, byte[] data, string fileName)
        {
            EncryptionJson json = new EncryptionJson();
            json.Type = "2";
            json.PrivateKey = hash;
            json.Data = data;
            string jsonReady = JsonSerializer.Serialize(json);
            File.WriteAllText(@$"{fileName}", jsonReady);
        }

        
        static void EncryptSym(SymmetricAlgorithm aesAlgorithm, string text,string fileName)  
        {  
            ICryptoTransform encryptor = aesAlgorithm.CreateEncryptor(aesAlgorithm.Key, aesAlgorithm.IV);  
  
            using (MemoryStream ms = new MemoryStream())  
            {  
                using (CryptoStream cs = new CryptoStream(ms,encryptor,CryptoStreamMode.Write))  
                {  
                    using (StreamWriter writer = new StreamWriter(cs))  
                    {   
                        writer.Write(text);  
                    }  
                }  
 
                byte[] encryptedDataBuffer = ms.ToArray();  

                File.WriteAllBytes(fileName, encryptedDataBuffer);  

                EncodedJsonSym(aesAlgorithm, encryptedDataBuffer,"encryptionInfoSym.json");

            }  
        }  

        static string DecryptSym(string fileName) 

        {  

            EncryptionJson jsonInfo = LoadJson("encryptionInfoSym.json");
            SymmetricAlgorithm aesAlgorithm = jsonInfo.Hash; 
            ICryptoTransform decryptor = aesAlgorithm.CreateDecryptor(aesAlgorithm.Key, aesAlgorithm.IV);  
   
            byte[] encryptedDataBuffer = File.ReadAllBytes(fileName);   
  
            using (MemoryStream ms = new MemoryStream(encryptedDataBuffer))  
            {  
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))  
                {  
                    using (StreamReader reader = new StreamReader(cs))  
                    {   
                        return reader.ReadToEnd();   
                    }  
                }  
            }  
        }  


        static void EncryptAsym(string text,string fileName)  
        {  
            RSACryptoServiceProvider rsa_key = new RSACryptoServiceProvider();  

            string publicKey = rsa_key.ToXmlString(false);  
            string privateKey = rsa_key.ToXmlString(true);

            UnicodeEncoding byteConverter = new UnicodeEncoding();  
            byte[] dataToEncrypt = byteConverter.GetBytes(text);  

            byte[] encryptedData;   
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())  
            {     
                rsa.FromXmlString(publicKey);   
                encryptedData = rsa.Encrypt(dataToEncrypt, false);   
            }  
            // Save the encypted data array into a file   
            File.WriteAllBytes(fileName, encryptedData);  

            EncodedJsonAsym(privateKey, encryptedData, "encryptionInfoAsym.json");
  
        }  
  
        static string DecryptAsym(string fileName)  
        {  

            EncryptionJson jsonInfo = LoadJson("encryptionInfoAsym.json");
            string privateKey = jsonInfo.PrivateKey;

            byte[] dataToDecrypt = File.ReadAllBytes(fileName);  
  
            byte[] decryptedData;  
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())  
            {  
                rsa.FromXmlString(privateKey);  
                decryptedData = rsa.Decrypt(dataToDecrypt, false);   
            }  
  
            UnicodeEncoding byteConverter = new UnicodeEncoding();  
            return byteConverter.GetString(decryptedData);   
        } 
        static void Main(string[] args)
        {   
            // Console.Write("Please input file path for encryption: ");
            // string filePathIn = Console.ReadLine();
            string filePath = "test.json";
            string info = FileToString(filePath);
            Console.WriteLine(info);
            
            
            Console.Write("Please choose 'e'(for encrypting) or 'd'(for decrypting) encription: ");
            string DecryptEncrypt = Console.ReadLine();
            Console.Write("Please choose 'a'(for assimetric) or 's'(for symmetric) encription: ");
            string Asymetric = Console.ReadLine();
            if (DecryptEncrypt == "d")
            {
                if (Asymetric == "a")
                {  
        
                    Console.WriteLine("Data: " + DecryptAsym("testAsym1.dat"));  
                }
                else
                {
                    SymmetricAlgorithm aes = new AesManaged();  

                    Console.WriteLine("Data: " + DecryptSym("testSym1.dat"));  
        
                }
            }
            else
            {

                if (Asymetric == "a")
                {  
        
                    EncryptAsym(info, "testAsym1.dat");  
                }
                else
                {
                    SymmetricAlgorithm aes = new AesManaged();  

                    EncryptSym(aes, info, "testSym1.dat");  
        
                }
            }


            

        }

    }
}
