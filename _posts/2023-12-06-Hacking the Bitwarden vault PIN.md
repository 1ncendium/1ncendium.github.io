---
title: Hacking the Bitwarden vault PIN
description: Hacking the Bitwarden vault PIN using Firefox extension data
author: remco
date: 2023-12-06 11:33:00 +0800
categories: [Research, Security]
tags: [research, security, pentesting]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/bitwarden-pin/bitwarden.png
---

Unlock with PIN is a Bitwarden feature to unlock your vault instead of using your masterkey. Bitwarden introduced this feature, but never raised the security issues within the extension or app. This blog post will show how to retrieve the PIN back from the Firefox extension data.

## Bitwarden unlock with PIN feature

Bitwarden's "Unlock with PIN" feature is a functionality designed to provide users with a quicker way to access their vault of stored passwords, secure notes, credit card information, and other sensitive data within the Bitwarden password manager.

![](/assets/img/posts/bitwarden-pin/1.png)

When users log in to their Bitwarden account, they typically use a master password to unlock their vault. However, the "Unlock with PIN" feature offers an alternative method for unlocking the vault quickly after the initial login.

## Firefox extensions local storage

In Firefox extensions, local storage refers to the ability of an extension to store data locally within the browser. This local storage is often used by extensions to save preferences, settings, or small amounts of data that need to be accessed or modified during the extension's runtime.

![](/assets/img/posts/bitwarden-pin/2.png)

## Locating the Local Storage database

The Local Storage is being saved inside a compressed sqlite database which can be found on all platforms under a different path. Bitwarden documented where their data is being stored for the extension and desktop app. [https://bitwarden.com/help/data-storage/](https://bitwarden.com/help/data-storage/). We are particularly interested in the extension part.

![](/assets/img/posts/bitwarden-pin/3.png)

Since I am using Linux to show this PoC, I refer to the Linux path here. But there is also one for Windows and MacOS. If an attacker compromised a machine running Firefox with the Bitwarden extension, he can go to this path and find the Bitwarden data. For this PoC we can go to the following directory:

```jsx
incendium@PC-01:~/.mozilla/firefox/tr2cgmb6.default-release/storage/default/moz-extension+++c8dd0025-9c20-49fb-a398-307c74e6f8b7^userContextId=4294967295/idb$ ls -la
total 68
drwxr-xr-x 3 incendium incendium  4096 Apr 13  2023 .
drwxr-xr-x 3 incendium incendium  4096 Apr 13  2023 ..
drwxr-xr-x 2 incendium incendium  4096 Apr 13  2023 3647222921wleabcEoxlt-eengsairo.files
-rw-r--r-- 1 incendium incendium 57344 Apr 13  2023 3647222921wleabcEoxlt-eengsairo.sqlite
```

We can see that here is a file called **“3647222921wleabcEoxlt-eengsairo.sqlite”.** We can copy this file to our own host and check the data.

## Extracting data from the database

When we have copied the file to our own host, we can see that it is indeed a SQlite3.x database:

![](/assets/img/posts/bitwarden-pin/4.png)

If we run sqlite3 with the database, we can see the tables and data:

![](/assets/img/posts/bitwarden-pin/5.png)

As we already knew, the data is compressed and we are not able to view it this way. We need a tool that can read the data from these indexedDB database files. Luckily, I came across this tool “moz-idb-edit” [https://gitlab.com/ntninja/moz-idb-edit](https://gitlab.com/ntninja/moz-idb-edit). We can clone the repository and use the Python script.

![](/assets/img/posts/bitwarden-pin/6.png)

We use the “>” to write the console output to a file instead. 

This will give us a file with the content of something like this:

![](/assets/img/posts/bitwarden-pin/7.png)

This contains the Bitwarden profile for our victim. We may use a JSON formatter to get a better understanding.

## Finding the PIN hash & number of rounds

Scrolling a bit down, we come across the PIN encrypted hash:

![](/assets/img/posts/bitwarden-pin/8.png)
The hash is being encrypted using the function:

$$
c=EncryptK(email, PIN)​(master key)
$$

where **K** is a key derivation function on disk. This implies that an attacker can brute-force the PIN if they are ever able to access the encrypted vault data kept on the device: With the guesses for the PIN, the attacker can verify if the decryption of the **c** is successful.

![](/assets/img/posts/bitwarden-pin/9.png)

the key derivation function for our case is PBKDF2 with 600000 iterations (+ HKDF), but that won't help with a 4 digit pin.

## Brute forcing the PIN

Bitwarden stated that “After **five** failed PIN attempts, the app will automatically log out of your account.” This is good, but since we have the offline stored hash we can brute force it using the encryption function to check if c matches our encrypted pinProtected hash. A 4 digit pin can be somewhere in the range of 0000-9999. 

Using this [https://github.com/ambiso/bitwarden-pin](https://github.com/ambiso/bitwarden-pin) Rust program from “ambiso”, we can brute force the pin using the exact method as described. I only modified it a bit so that is doesn’t require the XDG_CONFIG_HOME environment variable to be set. We also have to set the number of rounds. In our case “600000” as described.

![](/assets/img/posts/bitwarden-pin/10.png)

We can use our extension_data.json file as input data for the script:

![](/assets/img/posts/bitwarden-pin/11.png)

The script will find the encrypted PIN hash and format it to a correct hash. We can run the Rust program using cargo:

![](/assets/img/posts/bitwarden-pin/12.png)
It took about 10 seconds to find it.

## Conclusion

Bitwarden is still a very good password manager that I use myself. However, users should consider using the unlock with PIN feature. Also, for us to unlock the vault, the user should not select the “Lock with master password on Browser restart”. In that case, there would be a multi factor authentication that requires us to know the master password. 

Bitwarden does warn users on their website about the security issues regarding the PIN:

![](/assets/img/posts/bitwarden-pin/13.png)

But not in the extension/app itself.

**Sources:**

[https://bitwarden.com/help/unlock-with-pin/](https://bitwarden.com/help/unlock-with-pin/)

[https://ambiso.github.io/bitwarden-pin/](https://ambiso.github.io/bitwarden-pin/)

[https://github.com/ambiso/bitwarden-pin](https://github.com/ambiso/bitwarden-pin)

[https://bitwarden.com/help/data-storage/](https://bitwarden.com/help/data-storage/)

[https://stackoverflow.com/questions/54920939/parsing-fb-puritys-firefox-idb-indexed-database-api-object-data-blob-from-lin/59923297#59923297](https://stackoverflow.com/questions/54920939/parsing-fb-puritys-firefox-idb-indexed-database-api-object-data-blob-from-lin/59923297#59923297)

[https://gitlab.com/ntninja/moz-idb-edit](https://gitlab.com/ntninja/moz-idb-edit)
