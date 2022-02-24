using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System.Security.Cryptography;


namespace JPL_Internship
{   
    // ! GLOBAL
    public class EncryptedJson
    {
        public string jType { get; set; }
        public string jHash { get; set; }
        public string jData { get; set; }

        
        public string FileToString (string path)
        {   
            StreamReader r = new StreamReader(path);
            string jsonString = r.ReadToEnd();

            return jsonString;
        }
        public EncryptedJson LoadJson(string path)
        {
            string file = FileToString(path);
            EncryptedJson json = Newtonsoft.Json.JsonConvert.DeserializeObject<EncryptedJson>(file);
            return json;
        }

        public void EncodedJson(string type, string hash, string data, string encrFileName)
        {
            EncryptedJson json = new EncryptedJson();
            json.jType = type;
            json.jHash = hash;
            json.jData = data;
            string jsonReady = JsonSerializer.Serialize(json);
            File.WriteAllText(@$"{encrFileName}", jsonReady);
        }

    }

    public interface IEncryption{
        void Encrypt(string data, string encrFileName);
        void Decrypt(string encrFile, string key);

    }

    public class AsymmetricManager : IEncryption{

        private readonly string _type;

        private (string, string) GenerateAssymetricKeys(){
            
            var rsa = new RSACryptoServiceProvider(2048);  
            string publicKey = rsa.ToXmlString(false);// sending this to a friend
            string privateKey = rsa.ToXmlString(true); // private key

            return (publicKey, privateKey);   

        }

        private string AEncrypt(string publicKey, string data)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey); 
                var byteData = Encoding.UTF8.GetBytes(data);
                var encryptData = rsa.Encrypt(byteData, false);
                return Convert.ToBase64String(encryptData);
            }
        }

        private string ADecrypt(string cipherText, string privateKey)
        {

            using (var rsa = new RSACryptoServiceProvider())
            {
                var cipherByteData = Convert.FromBase64String(cipherText);
                rsa.FromXmlString(privateKey); 

                var encryptData = rsa.Decrypt(cipherByteData, false);
                return Encoding.UTF8.GetString(encryptData);
            }
        }

        public AsymmetricManager()
        {
            _type = "1";

        }

        public void Encrypt(string data, string encrFileName)
        {

            EncryptedJson json = new EncryptedJson();

            string rawData = json.FileToString(data);

            var asymKeys = GenerateAssymetricKeys();
            string publicKey = asymKeys.Item1;
            string privateKey = asymKeys.Item2;
            Console.WriteLine();
            // Console.WriteLine("Public key: ");
            // Console.WriteLine(publicKey);
            Console.WriteLine("Private key: ");
            Console.WriteLine(privateKey);
            Console.WriteLine();

            var dataToEncrypt = AEncrypt(publicKey, rawData);

            json.EncodedJson(_type, publicKey, dataToEncrypt, encrFileName);
            Console.WriteLine($"Data ecnrypted successfully in {encrFileName} -- Type: {_type}");
        }
        public void Decrypt(string encrFile, string key)
        {
            EncryptedJson json = new EncryptedJson();
            EncryptedJson encrInfo = json.LoadJson(encrFile);
            string publicKey_decr = encrInfo.jHash;
            string e_decr = encrInfo.jData;

            var decrMessage = ADecrypt(e_decr, key);
            Console.WriteLine();
            Console.WriteLine("Decrypted message: " + decrMessage);
            Console.WriteLine($"Data decrypted successfully from {encrFile} -- Type: {_type}");
        }
        
    }
    public class SymmetricManager : IEncryption{

        private readonly string _type;

        private Aes GenerateCryptoKey(){
            Aes aes = Aes.Create();  
            aes.GenerateIV();  
            aes.GenerateKey();
            return aes;
        }
        private string ConvertCryptoKeyToStr(Aes aes){
            string sKey = Convert.ToBase64String(aes.IV);
            return sKey;
        }
        private byte[] ConvertCryptoKeyToByte(string key){
            byte[] byteKey= Convert.FromBase64String(key);
            return byteKey;
        }
        private string GenerateHash(string data)
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

        private string SEncrypt(string key, string data)  
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
  
        private string SDecrypt(string key, string cipherText)  
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

        public SymmetricManager()
        {
            _type = "2";

        }

        public void Encrypt(string data, string encrFileName)
        {

            EncryptedJson json = new EncryptedJson();

            string rawData = json.FileToString(data);

            var key = ConvertCryptoKeyToStr(GenerateCryptoKey());  

            Console.WriteLine();
            Console.WriteLine("Symmetric Key: ");
            Console.WriteLine(key);
            Console.WriteLine();

            var dataToEncrypt = SEncrypt(key, rawData);  
            var hash = GenerateHash(rawData);

            json.EncodedJson(_type, hash, dataToEncrypt, encrFileName);
            Console.WriteLine($"Data ecnrypted successfully in {encrFileName} -- Type: {_type}");
        }
        public void Decrypt(string encrFile, string key)
        {
            EncryptedJson json = new EncryptedJson();
            EncryptedJson encrInfo = json.LoadJson(encrFile);

            string h_decr = encrInfo.jHash;
            string e_decr = encrInfo.jData;
            
            string decrypted_e = SDecrypt(key, e_decr);
            string h1 = GenerateHash(decrypted_e);

            if (string.Equals(h_decr, h1))
            {
                Console.WriteLine();
                Console.WriteLine("Decrypted Message: " + decrypted_e);
            }
            Console.WriteLine($"Data decrypted successfully from {encrFile} -- Type: {_type}");
        }
        
    }

    public abstract class EncryptionFactory
    {
        public abstract IEncryption Create();
    }
    public class AssymetricFactory:EncryptionFactory
    {
        public override IEncryption Create()
        {
            return new AsymmetricManager();
        }
        
    }
    public class SymmetricFactory:EncryptionFactory
    {
        public override IEncryption Create()
        {
            return new SymmetricManager();
        }
        
    }

    public enum EncryptionTypes
    {
        Asymmetric,
        Symmetric
    }

    public class Factory
    {
        private readonly Dictionary<EncryptionTypes, EncryptionFactory> _factories;
        public Factory()
        {
            _factories = new Dictionary<EncryptionTypes, EncryptionFactory>
            {
                { EncryptionTypes.Asymmetric, new AssymetricFactory() },
                { EncryptionTypes.Symmetric, new SymmetricFactory() },
            };
        }

        public IEncryption NewEncryption(EncryptionTypes action) =>_factories[action].Create();
    }

    class Program
    {
        
        static void Main(string[] args)
        {   

            var factory = new Factory().NewEncryption(EncryptionTypes.Symmetric);
            factory.Encrypt("test.json", "sym.json");
            

        }

    }
}
