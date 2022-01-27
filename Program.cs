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
        public string Hash { get; set; }
        public string Data { get; set; }
    }
    class Program
    {
        static string EncryptA(string data, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey); 
                var byteData = Encoding.UTF8.GetBytes(data);
                var encryptData = rsa.Encrypt(byteData, false);
                return Convert.ToBase64String(encryptData);
            }
        }

        static string DecryptA(string cipherText, string privateKey)
        {

            using (var rsa = new RSACryptoServiceProvider())
            {
                var cipherByteData = Convert.FromBase64String(cipherText);
                rsa.FromXmlString(privateKey); 

                var encryptData = rsa.Decrypt(cipherByteData, false);
                return Encoding.UTF8.GetString(encryptData);
            }
        }
        static string EncryptS(string key, string plainText)  
        {  
            byte[] iv = new byte[16];  
            byte[] array;  
  
            using (Aes aes = Aes.Create())  
            {  
                aes.Key = Encoding.UTF8.GetBytes(key);  
                aes.IV = iv;  
  
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);  
  
                using (MemoryStream memoryStream = new MemoryStream())  
                {  
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))  
                    {  
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))  
                        {  
                            streamWriter.Write(plainText);  
                        }  
  
                        array = memoryStream.ToArray();  
                    }  
                }  
            }  
  
            return Convert.ToBase64String(array);  
        }  
  
        static string DecryptS(string key, string cipherText)  
        {  
            byte[] iv = new byte[16];  
            byte[] buffer = Convert.FromBase64String(cipherText);  
  
            using (Aes aes = Aes.Create())  
            {  
                aes.Key = Encoding.UTF8.GetBytes(key);  
                aes.IV = iv;  
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);  
  
                using (MemoryStream memoryStream = new MemoryStream(buffer))  
                {  
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))  
                    {  
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))  
                        {  
                            return streamReader.ReadToEnd();  
                        }  
                    }  
                }  
            }  
        }  
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
        static Aes GenerateCryptoKey(){
            Aes aes = Aes.Create();  
            aes.GenerateIV();  
            aes.GenerateKey();
            return aes;
        }
        static string ConvertCryptoKeyToStr(Aes aes){
            string sKey = Convert.ToBase64String(aes.IV);
            return sKey;
        }
        static byte[] ConvertCryptoKeyToByte(string key){
            byte[] byteKey= Convert.FromBase64String(key);
            return byteKey;
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

        static void EncodedJson(string type, string hash, string data, string fileName)
        {
            EncryptionJson json = new EncryptionJson();
            json.Type = "1";
            json.Hash = hash;
            json.Data = data;
            string jsonReady = JsonSerializer.Serialize(json);
            File.WriteAllText(@$"{fileName}", jsonReady);
        }


        static void Main(string[] args)
        {   
            Console.Write("Please choose 'a'(for assimetric) or 's'(for symmetric) encription: ");
            string Asymetric = Console.ReadLine();

            string filePath = "test.json";
            string info = FileToString(filePath);
            string encrFileName = "msg_send.json";


            if (Asymetric == "s"){
                // * ENCRYPTING - Symmetric

                var key = ConvertCryptoKeyToStr(GenerateCryptoKey());  

                Console.WriteLine("Symmetric Key: "+ key);

                var e = EncryptS(key, info);  
                var h = GenerateHash(info);
                

                EncodedJson("1",h, e,encrFileName);

                // * DECRYPTING - Symmetric

                EncryptionJson encrInfo = LoadJson(encrFileName);
                string h_decr = encrInfo.Hash;
                string e_decr = encrInfo.Data;

                string decrypted_e = DecryptS(key, e_decr);
                Console.WriteLine(decrypted_e);

                string h1 = GenerateHash(decrypted_e);

                Console.WriteLine("Message decrypted successfully: " + string.Equals(h_decr, h1));
            }
            else{
                // * ENCRYPTING - Assymmetric

                var rsa = new RSACryptoServiceProvider(2048);  
 
                string publicKey = rsa.ToXmlString(false);// sending this to a friend
                string privateKey = rsa.ToXmlString(true); // private key   

                var e = EncryptA(info, publicKey);
                EncodedJson("2",publicKey,e,encrFileName);
                
                // * DECRYPTING - Assymmetric

                EncryptionJson encrInfo = LoadJson(encrFileName);
                string publicKey_decr = encrInfo.Hash;
                string e_decr = encrInfo.Data;

                var decrMessage = DecryptA(e_decr, privateKey);
                Console.WriteLine("Encrypted message: " + decrMessage);

            }


            
            

        }

    }
}
