using System;
using System.Collections;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;
using System.Data.SqlClient;
using System.Text;
using System.Security.Cryptography;
using System.IO;

public partial class compose : System.Web.UI.Page
{
    conclass obj = new conclass();

    static string filename;
    static string up_rootpat;
    static string up_file_pat;
    static string servr_plainrootpat;
    static string servr_plainfilpat;
    static string servr_stegroot_pat;
    string ex, ex1;
    static string cyphertext;
    static string cyphertxt_extractd;
    static string decryptd_txt;

    protected void Page_Load(object sender, EventArgs e)
    {
        if (!IsPostBack)
        {
            string qry = "select uname from reg where uname!='" + Session["uname"].ToString() + "'";
            SqlDataReader rd = obj.getdataReader(qry);
            while (rd.Read())
            {
                DropDownList1.Items.Add(rd[0].ToString());
            }
            rd.Close();
        }
    }
    protected void Button4_Click(object sender, EventArgs e)
    {
        string passPhrase = "rhjki5rw$&^";        // can be any string
        string saltValue = "wd7ytuj#5(";        // can be any string
        //SHA1 is more secure than MD5
        string hashAlgorithm = "SHA1";             // can be "MD5"
        /// Number of iterations used to generate password. One or two iterations
        /// should be enough.
        int passwordIterations = 1;                  // can be any number
        string initVector = "@1B2c3D4e5F6g7H8"; // must be 16 bytes
        int keySize = 128;

        cyphertext = Encrypt(TextBox1.Text, passPhrase, saltValue, hashAlgorithm, passwordIterations, initVector, keySize);
       
        embedd(cyphertext, TextBox2.Text);

    }

    public static string Encrypt(string plainText,
                                string passPhrase,
                                string saltValue,
                                string hashAlgorithm,
                                int passwordIterations,
                                string initVector,
                                int keySize)
    {
        // Convert strings into byte arrays.
        // Let us assume that strings only contain ASCII codes.
        // If strings include Unicode characters, use Unicode, UTF7, or UTF8 
        // encoding.
        byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
        byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

        // Convert our plaintext into a byte array.
        // Let us assume that plaintext contains UTF8-encoded characters.
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

        // First, we must create a password, from which the key will be derived.
        // This password will be generated from the specified passphrase and 
        // salt value. The password will be created using the specified hash 
        // algorithm. Password creation can be done in several iterations.
        PasswordDeriveBytes password = new PasswordDeriveBytes(
                                                        passPhrase,
                                                        saltValueBytes,
                                                        hashAlgorithm,
                                                        passwordIterations);

        // Use the password to generate pseudo-random bytes for the encryption
        // key. Specify the size of the key in bytes (instead of bits).
        byte[] keyBytes = password.GetBytes(keySize / 8);

        // Create uninitialized Rijndael encryption object.
        RijndaelManaged symmetricKey = new RijndaelManaged();

        // It is reasonable to set encryption mode to Cipher Block Chaining
        // (CBC). Use default options for other symmetric key parameters.
        symmetricKey.Mode = CipherMode.CBC;

        // Generate encryptor from the existing key bytes and initialization 
        // vector. Key size will be defined based on the number of the key 
        // bytes.
        ICryptoTransform encryptor = symmetricKey.CreateEncryptor(
                                                         keyBytes,
                                                         initVectorBytes);

        // Define memory stream which will be used to hold encrypted data.
        MemoryStream memoryStream = new MemoryStream();

        // Define cryptographic stream (always use Write mode for encryption).
        CryptoStream cryptoStream = new CryptoStream(memoryStream,
                                                     encryptor,
                                                     CryptoStreamMode.Write);
        // Start encrypting.
        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

        // Finish encrypting.
        cryptoStream.FlushFinalBlock();

        // Convert our encrypted data from a memory stream into a byte array.
        byte[] cipherTextBytes = memoryStream.ToArray();

        // Close both streams.
        memoryStream.Close();
        cryptoStream.Close();

        // Convert encrypted data into a base64-encoded string.
        string cipherText = Convert.ToBase64String(cipherTextBytes);

        // Return encrypted string.
        return cipherText;
    }

    public string embedd(string txt_toembedd, string filnam_tosave)
    {

        servr_stegroot_pat = Server.MapPath("~\\stegnoimage\\");
        Session["stegimgfilnam"] = filnam_tosave;
        try
        {
            FileStream fs = new FileStream(servr_plainrootpat + Session["fileupld_filenam"].ToString(), FileMode.Open, FileAccess.Read);
            BinaryReader br = new BinaryReader(fs);
            FileStream fs1 = new FileStream(servr_stegroot_pat + TextBox2.Text, FileMode.CreateNew, FileAccess.Write);
            BinaryWriter bw = new BinaryWriter(fs1);
            string actual;

            actual = txt_toembedd; //txtmsg.Text;


            //string data1 = actual;   //Encrypt(actual, textBox4.Text);

            //TextBox1.Text = data1;


            byte[] byteMessage = System.Text.Encoding.ASCII.GetBytes(actual);

            byte[] data = br.ReadBytes(1000);
            bw.Write(data);



            int Skip = (int)(fs.Length - 1010) / byteMessage.Length;

            for (int i = 0; i < byteMessage.Length; ++i)
            {
                byte[] part = br.ReadBytes(Skip);
                part[0] = byteMessage[i];
                bw.Write(part);

            }

            byte[] Remaining = br.ReadBytes((int)(fs.Length - fs.Position));
            byte MsgLen = (byte)byteMessage.Length;
            Remaining[Remaining.Length - 10] = MsgLen;
            bw.Write(Remaining);

            bw.Flush();
            bw.Close();
            br.Close();
            fs.Close();
            fs1.Close();
            Label4.Text = "Data Embedded Successfully...and hidden";
            Label4.Visible = true;
        }

        catch (Exception x)
        {
            ex = x.Message;
        }
        return ex;

    }


    protected void Button2_Click(object sender, EventArgs e)
    {
        filename = FileUpload1.PostedFile.FileName;
        Session["fileupld_filenam"] = filename;
        up_rootpat = "~\\plainimage\\";
        up_file_pat = up_rootpat + filename;
        servr_plainrootpat = Server.MapPath("~\\plainimage\\");
        servr_plainfilpat = servr_plainrootpat + filename;
        FileUpload1.PostedFile.SaveAs(servr_plainfilpat);
        Image1.ImageUrl = up_file_pat;
    }
    protected void Button1_Click(object sender, EventArgs e)
    {
         string stegimgpat_toextract = servr_stegroot_pat + Session["stegimgfilnam"].ToString();
         string qry1 = "insert into compose values('" + DropDownList1.SelectedItem.ToString() + "','" + Session["uname"].ToString() + "','" + filename + "','" + stegimgpat_toextract + "','" + DateTime.Now.ToShortDateString() + "','0')";
         obj.exeNonQry(qry1);
    }
    protected void Button5_Click(object sender, EventArgs e)
    {

    }

    protected void DropDownList1_SelectedIndexChanged(object sender, EventArgs e)
    {

    }
}
