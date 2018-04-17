# EASSniper
EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS). 

This tool is based on the great work by Beau Bullock (@dafthack)/Fehrman and the MailSniper tool. EASSniper focuses specifically on Exchange Active Sync (EAS), consisting of two main functions:

Invoke-UsernameHarvestEAS - Attempt to harvest active usernames via EAS
Invoke-PasswordSprayEAS - Password spray attack performed against EAS 

# Parameters
ExchHostname - The hostname of the Exchange server to connect to
UserList -  List of usernames 1 per line to to attempt to check for validity 
OutFile - Outputs the results to a text file
Password - A single password to attempt a password spray with
Domain - Domain name to prepend to usernames
Threads - Number of password spraying threads to run

# Examples
Invoke-UsernameHarvestEAS -ExchHostname mail.domain.com -UserList .\userlist.txt -Threads 1 -OutFile eas-valid-users.txt

Description
This command will connect to EAS at https://mail.domain.com/Microsoft-Server-ActiveSync/ and attempt to harvest a list of valid usernames by password spraying the provided list of usernames with a single password over 1 thread and write to a file called eas-valid-users.txt.


Invoke-PasswordSprayEAS -ExchHostname mail.domain.com -UserList .\userlist.txt -Password Foobar -Threads 15 -OutFile owa-sprayed-creds.txt

Description
This command will connect to EAS at https://mail.domain.com/Microsoft-Server-ActiveSync/ and password spray utilizing a single password 'Foobar'a to a list of usernames 'userlist.txt' and write to a file called 'owa-sprayed-creds.txt'.


