using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System.Security.Cryptography;


namespace JPL_Internship
{   
    public class EncryptionJson : Encryption
    {
        public string Type { get; set; }
        public string Hash { get; set; }
        public string Data { get; set; }

        
        public string FileToString (string path)
        {   
            StreamReader r = new StreamReader(path);
            string jsonString = r.ReadToEnd();

            return jsonString;
        }

        public EncryptionJson LoadJson(string path)
        {
            string file = FileToString(path);
            EncryptionJson json = Newtonsoft.Json.JsonConvert.DeserializeObject<EncryptionJson>(file);
            return json;
        }

        public void EncodedJson(string type, string hash, string data, string encrFileName)
        {
            EncryptionJson json = new EncryptionJson();
            json.Type = "1";
            json.Hash = hash;
            json.Data = data;
            string jsonReady = JsonSerializer.Serialize(json);
            File.WriteAllText(@$"{encrFileName}", jsonReady);
        }

    }

    public class Encryption{
        public string data { get; set; }
        public string encrFileName { get; set; }

    }
    public class AssymmetricEncryption : Encryption{


        public string Encrypt(string publicKey, string data)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey); 
                var byteData = Encoding.UTF8.GetBytes(data);
                var encryptData = rsa.Encrypt(byteData, false);
                return Convert.ToBase64String(encryptData);
            }
        }

        public string Decrypt(string cipherText, string privateKey)
        {

            using (var rsa = new RSACryptoServiceProvider())
            {
                var cipherByteData = Convert.FromBase64String(cipherText);
                rsa.FromXmlString(privateKey); 

                var encryptData = rsa.Decrypt(cipherByteData, false);
                return Encoding.UTF8.GetString(encryptData);
            }
        }

        public (string, string) GenerateAssymetricKeys(){
            
            var rsa = new RSACryptoServiceProvider(2048);  
            string publicKey = rsa.ToXmlString(false);// sending this to a friend
            string privateKey = rsa.ToXmlString(true); // private key

            return (publicKey, privateKey);   

        }

        public void Execute(Encryption encryption, EncryptionJson json){
            AssymmetricEncryption assymmetricEncryption = new AssymmetricEncryption();

            var asymKeys = GenerateAssymetricKeys();
            string publicKey = asymKeys.Item1;
            Console.WriteLine("Public key: " + publicKey);
            string privateKey = asymKeys.Item2;

            var data = Encrypt(publicKey, encryption.data);
            json.EncodedJson("2",publicKey, data, encryption.encrFileName);
            
            // * DECRYPTING - Assymmetric

            EncryptionJson encrInfo = json.LoadJson(encryption.encrFileName);
            string publicKey_decr = encrInfo.Hash;
            string e_decr = encrInfo.Data;

            var decrMessage = Decrypt(e_decr, privateKey);
            Console.WriteLine("Encrypted message: " + decrMessage);
        }

    }
    public class SymmetricEncryption : Encryption{

        public Aes GenerateCryptoKey(){
            Aes aes = Aes.Create();  
            aes.GenerateIV();  
            aes.GenerateKey();
            return aes;
        }
        public string ConvertCryptoKeyToStr(Aes aes){
            string sKey = Convert.ToBase64String(aes.IV);
            return sKey;
        }
        public byte[] ConvertCryptoKeyToByte(string key){
            byte[] byteKey= Convert.FromBase64String(key);
            return byteKey;
        }
        public string GenerateHash(string data)
        {
            StringBuilder stringBdr = new StringBuilder(); // repeated modifications to a string

            byte[] textBytes = Encoding.ASCII.GetBytes(data); // converting string to into a bytes array

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
        public string Encrypt(string key, string data)  
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
                            streamWriter.Write(data);  
                        }  
  
                        array = memoryStream.ToArray();  
                    }  
                }  
            }  
  
            return Convert.ToBase64String(array);  
        }  
  
        public string Decrypt(string key, string cipherText)  
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

        public void Execute(Encryption encryption, EncryptionJson json){
            var key = ConvertCryptoKeyToStr(GenerateCryptoKey());  
            Console.WriteLine("Symmetric Key: "+ key);

            var data = Encrypt(key, encryption.data);  
            var hash = GenerateHash(encryption.data);

            json.EncodedJson("1",hash, data, encryption.encrFileName);

            EncryptionJson encrInfo = json.LoadJson(encryption.encrFileName);

            string h_decr = encrInfo.Hash;
            string e_decr = encrInfo.Data;

            string decrypted_e = Decrypt(key, e_decr);
            string h1 = GenerateHash(decrypted_e);

            Console.WriteLine("Message decrypted successfully: " + string.Equals(h_decr, h1));

        }

    }
    class Program
    {
        
        static void Main(string[] args)
        {   

            Console.Write("Please choose 'a'(for assimetric) or 's'(for symmetric) encription: ");
            string Asymetric = Console.ReadLine();

            string filePath = "test.json";

            Encryption encryption = new Encryption();
            EncryptionJson json = new EncryptionJson();
            encryption.data = json.FileToString(filePath);
            encryption.encrFileName = "message.json";

            if (Asymetric == "s"){

                SymmetricEncryption symmetricEncryption = new SymmetricEncryption();
                symmetricEncryption.Execute(encryption, json);

            }
            else{

                AssymmetricEncryption assymmetricEncryption = new AssymmetricEncryption();
                assymmetricEncryption.Execute(encryption, json);

            }


            
            

        }

    }
}
