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
        public string SHash { get; set; }
        public byte[] AHash { get; set; }
        public byte[] ASignature { get; set; }
        public string APublicKey { get; set; }
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

        public void AEncodedJson(string type, byte[] hash, byte[] signature, string publicKey, string data, string encrFileName)
        {
            EncryptedJson json = new EncryptedJson();
            json.jType = type;
            json.AHash = hash;
            json.ASignature = signature;
            json.APublicKey = publicKey;
            json.jData = data;
            string jsonReady = JsonSerializer.Serialize(json);
            File.WriteAllText(@$"{encrFileName}", jsonReady);
        }
        public void SEncodedJson(string type, string hash, string data, string encrFileName)
        {
            EncryptedJson json = new EncryptedJson();
            json.jType = type;
            json.SHash = hash;
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
        private RSACryptoServiceProvider rsa;

        private (byte[],string) GenerateHash(string data)
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

                return (generateHash,stringBdr.ToString());
            }

        }

        private byte[] SignData(byte[] hashOfDataToSign, RSAParameters privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);
                
                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);                
                rsaFormatter.SetHashAlgorithm("SHA1");

                return rsaFormatter.CreateSignature(hashOfDataToSign);
            }
        }

        private bool VerifySignature(byte[] hashOfDataToSign, byte[] signature, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(publicKey);

                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA1");

                return rsaDeformatter.VerifySignature(hashOfDataToSign, signature);
            }
        }   


        private (RSAParameters, RSAParameters) GenerateAssymetricKeys(){
            
            rsa = new RSACryptoServiceProvider(2048);  
            RSAParameters publicKey = rsa.ExportParameters(false); // sending this to a friend
            RSAParameters privateKey = rsa.ExportParameters(true); // private key

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
            var asymKeys = GenerateAssymetricKeys();

            string rawData = json.FileToString(data);

            // Digital Signature

            var hashedDocument = GenerateHash(rawData);

            byte[] ByteHashedData = hashedDocument.Item1;
            string StrHashedData = hashedDocument.Item2;
    
            var signature = SignData(ByteHashedData, asymKeys.Item2);
            Console.WriteLine();
            Console.WriteLine("Digital Signature = " + Convert.ToBase64String(signature));

            
            string publicKey = rsa.ToXmlString(false);
            // byte[] publicKey2 = rsa.ExportRSAPublicKey();
            // string b64PublicKey = Convert.ToBase64String(publicKey2);


            string privateKey = rsa.ToXmlString(true);
            Console.WriteLine();
            Console.WriteLine("Public key: ");
            Console.WriteLine(publicKey);
            // Console.WriteLine(b64PublicKey);
            Console.WriteLine("Private key: ");
            Console.WriteLine(privateKey);
            Console.WriteLine();
            

            var dataToEncrypt = AEncrypt(publicKey, rawData);

            json.AEncodedJson(_type, ByteHashedData, signature, publicKey, dataToEncrypt, encrFileName);
            Console.WriteLine($"Data ecnrypted successfully in {encrFileName} -- Type: {_type}");
        }
        public void Decrypt(string encrFile, string privateKey)
        {
            EncryptedJson json = new EncryptedJson();
            EncryptedJson encrInfo = json.LoadJson(encrFile);
            byte[] hashedDocument = encrInfo.AHash;
            byte[] signature = encrInfo.ASignature;
            string publicKey = encrInfo.APublicKey;
            string e_decr = encrInfo.jData;
            var verified = VerifySignature(hashedDocument, signature, publicKey);

            if (verified){
                Console.WriteLine("--- VERIFIED ---");
                Console.WriteLine();        
                var decrMessage = ADecrypt(e_decr, privateKey);
                Console.WriteLine();
                Console.WriteLine("Decrypted message: " + decrMessage);
                Console.WriteLine($"Data decrypted successfully from {encrFile} -- Type: {_type}");

            }
            else{
                Console.WriteLine("--- NOT VERIFIED ---");
            }

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

            json.SEncodedJson(_type, hash, dataToEncrypt, encrFileName);
            Console.WriteLine($"Data ecnrypted successfully in {encrFileName} -- Type: {_type}");
        }
        public void Decrypt(string encrFile, string key)
        {
            EncryptedJson json = new EncryptedJson();
            EncryptedJson encrInfo = json.LoadJson(encrFile);

            string h_decr = encrInfo.SHash;
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

            var factory = new Factory().NewEncryption(EncryptionTypes.Asymmetric);
            factory.Decrypt("asym2.json",
            "<RSAKeyValue><Modulus>xF1F4+IwVhuo4y/60i+6JnJjw5wbrpCcjv0Mhj3EyEDDdP3k8k0gAxeUbLqQTpcBYyyV+sQzHt0qlbC+lxCGf9aIl9BcxkC3z312y7mBLi0tAwxQnwn5t4tBP5TIaTD/PjlEIAliItrOnrY+RPLWckxdQKOrny8MSFJmz4TVf9Qsm9f49+8GrwxdhzUbwZ1IripleNtKptOIJH1gJEIks8F6alP5eGjNPjFE8tKyMrYfSxWZ/Z0LIyqf6uhbeyLscKXrrMzq7H2xjUevmPRSkoGrqPCBQO6jBTcRbczfjl4F8IJuCUm/YjyqfYaL7bhhxzA5rlTSsTPRy4ISwiZYZQ==</Modulus><Exponent>AQAB</Exponent><P>6OUlEGZhULgEGibXjg3py69vMoJPWqLoCfc1t/qN4qR+AywLozHGkUTCTA/TpWoDlTU6m+FXEJBvEi551/zTtVcIUTHx1RUF21pKvFxKWOdvQAQ3juSzUXWnE+uzcPDIYOMo9veZWMkMHCNMncmkQFb2iJ7bn2nR4wy/38wKEs0=</P><Q>19hamRib5No+n3EmwCZUrIvr+BX5pDCvsClOgs2F/68Q9fhjY1cu0V543JvkD5wVy3d9pt7cri8nNBGJvJ2wfb/LzLv0auKuRscArLtgzk+VHrx9zXugRIcWNR8WTkesLYSSug3Ko+h1zSN3IWfRWBMbZ8fpw7NEyZV16yw4S/k=</Q><DP>lNZUgI2dZbOkU349RbiYkKZ2XwYuZpMzzaKiPwiuAojzS12rtkjKSO5zaZ63uL/uuD2DTjmNpbVYdnsjPSiDuCF93D4Z+f5sdsnWd1hX30dQrs3DH9wCyW1yMGXykJwgwuKJvINyCe66gYUBotlJ0iCBf8BeRRugmgT83q6MRYU=</DP><DQ>iGPKO9t1BtNxpsaVOe3+q1lvLkCUks/A9IvldHnyJnK1QPhHtUot51bPAHfxUHvMudkzqPJCeD6Lgzdh1bG/CHbdjO1nsPK0NT0ijAOLVFKtY9Kvm9x2lVbXDZIrQiPABLM1FCQK3C/T4GB8srsraYAJXTbR3Du3R7oN3SEAIeE=</DQ><InverseQ>34zzjNC0KBELYjHPTcICTIpJyIvZ9cLLtx2HG2K0sM99f/iowkeBGKnu0BtGe2Ix/PKtSfS1ujbfRRnv8V7JdUITrX2hpArUatrw8ZkUsZxudVVdBy7a9dWQJgnk/nFI25ZAcq5lyMqEesl/ydV/b9mzKoArEhUhfTSESozUIr4=</InverseQ><D>giyrRnUOQic4ANQv3OMS7qXqiSSWHVV01D3g7aVJLM/yQz6FZjPGwwYAuUu8mrz0iIBoNMOYeB96OZ3f21lzMJBSIQJaXntM31p3RHsHrkr4igrB74y3ZPwGF1ZUvZdjviZMiUhvLFgNnZ2HDkJF86O4Nj/KaE7SP6eQzIVs273tEItOtAjq7cCm0tBr2ApA+btzdqjFZ5U/79Zc9A0ep5MTq/gpLKBAzdXVzTWRHOAUZfvO98E0iNcx0l6zkPjoOykg0issrfZpA9dMDi0pdw9LyrBatCNVsoa5Vxodd5a8TYoih9DrDingKKNfAnbr8rU/Mxddirz/g68z8B0XwQ==</D></RSAKeyValue>");
            // factory.Encrypt("test.json","asym2.json");
            
        }

    }
}
