open System
open System.IO
open System.Security.Cryptography
open System.Text

let filePath = "notes.enc"

let getPasswordKey (password: string) =
    let salt = Encoding.UTF8.GetBytes("notepad_salt") // fixed salt
    use kdf = new Rfc2898DeriveBytes(password, salt, 100_000)
    kdf.GetBytes(32), kdf.GetBytes(16) // 256-bit key, 128-bit IV

let encrypt (plainText: string) (password: string) =
    let key, iv = getPasswordKey password
    use aes = Aes.Create()
    aes.Key <- key
    aes.IV <- iv
    use encryptor = aes.CreateEncryptor()
    use ms = new MemoryStream()
    use cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)
    use sw = new StreamWriter(cs)
    sw.Write(plainText)
    sw.Close()
    Convert.ToBase64String(ms.ToArray())

let decrypt (cipherText: string) (password: string) =
    let key, iv = getPasswordKey password
    use aes = Aes.Create()
    aes.Key <- key
    aes.IV <- iv
    use decryptor = aes.CreateDecryptor()
    let bytes = Convert.FromBase64String(cipherText)
    use ms = new MemoryStream(bytes)
    use cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)
    use sr = new StreamReader(cs)
    try
        sr.ReadToEnd()
    with
    | _ -> "Decryption failed. Wrong password?"

let saveNote () =
    Console.Write("Enter password: ")
    let pw = Console.ReadLine()
    Console.Write("Write your note: ")
    let note = Console.ReadLine()
    let encrypted = encrypt note pw
    File.WriteAllText(filePath, encrypted)
    Console.WriteLine("Note saved.\n")

let readNote () =
    if not (File.Exists filePath) then
        Console.WriteLine("No saved note found.\n")
    else
        Console.Write("Enter password to read: ")
        let pw = Console.ReadLine()
        let encrypted = File.ReadAllText(filePath)
        let decrypted = decrypt encrypted pw
        Console.WriteLine($"\nDecrypted note:\n{decrypted}\n")

[<EntryPoint>]
let main _ =
    let mutable running = true
    while running do
        Console.WriteLine("== Encrypted Notepad ==")
        Console.WriteLine("1) Write Note")
        Console.WriteLine("2) Read Note")
        Console.WriteLine("3) Exit")
        Console.Write("Choose: ")
        match Console.ReadLine() with
        | "1" -> saveNote()
        | "2" -> readNote()
        | "3" -> running <- false
        | _ -> Console.WriteLine("Invalid choice.\n")
    0
