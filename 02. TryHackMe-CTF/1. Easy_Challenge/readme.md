<img width="1053" height="87" alt="image" src="https://github.com/user-attachments/assets/d567e37d-93a8-4aad-8d7b-49eb17a81cc6" /><h1 align="center"> Simple CTF </h1>

<img width="1323" height="186" alt="image" src="https://github.com/user-attachments/assets/01ade0f1-70a6-4bb0-940f-74b4b496f34d" />




## Start Lab:
<img width="822" height="616" alt="image" src="https://github.com/user-attachments/assets/06cb6830-f0b3-4864-920b-a60c9ccddb81" />


This our what we will find:
<img width="814" height="789" alt="image" src="https://github.com/user-attachments/assets/7f0b3d65-091c-41b2-8d71-30b9c0e7da75" />


## Start Machine
After start machine now i see my target have IP `10.48.186.93`:
<img width="810" height="491" alt="image" src="https://github.com/user-attachments/assets/3c789788-1f34-4f43-b62b-b42c2bbc5886" />


In this i do this lab with my KALI Linux, and then i open my `OpenVPN`:
<img width="552" height="378" alt="image" src="https://github.com/user-attachments/assets/3a2b8e2b-3df1-4795-93a9-9b7cd41d3439" />

And then on KalI
````
cd Desktop
ls
cd THM
ls
sudo openvpn eu-west-1-HelloHello89-regular.ovpn 
````
<img width="1440" height="844" alt="image" src="https://github.com/user-attachments/assets/63488460-358b-4bda-9737-6d7735595bf2" />

After open one more `Terminal`, just press `Ctrl + Shift + T`:
````
mkdir simple-ctf
cd simple-ctf
````
<img width="555" height="212" alt="image" src="https://github.com/user-attachments/assets/48309a18-1a49-429a-8425-f7db7b6f3c7e" />

After verify to target machine:
````
ping 10.48.186.93
````
<img width="653" height="302" alt="image" src="https://github.com/user-attachments/assets/c62abd2a-12a6-4f5a-b29a-ae5ec097c337" />


---


# Task 1
<img width="810" height="794" alt="image" src="https://github.com/user-attachments/assets/77611e4c-f32b-4a64-9ed7-0d23c47a106d" />

## Question 1:
How many services are running under port 1000?
<img width="1084" height="93" alt="image" src="https://github.com/user-attachments/assets/977327ef-a7ee-4ee0-94d7-43b30cc5c355" />

- Scan target:
````
nmap 10.48.186.93 -sVC -Pn -T4 -oN first.txt
````
<img width="968" height="787" alt="image" src="https://github.com/user-attachments/assets/66e68019-d9f7-41cc-af8b-23ad9013b3fe" />

After we wait it to scan afew minute, Now we got the result. 

So in this `services are running under port 1000` have `2`
1. 21/tcp   open  ftp     vsftpd 3.0.3
2. 80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))

And why not `2222`? -> Cause it over `1000` service.

- Now we found the correct answer is:
````
2
````
<img width="1053" height="87" alt="image" src="https://github.com/user-attachments/assets/46dc4cbb-c648-4eab-a21e-9e1d3901fda3" />

---

## Question 2:
What is running on the higher port?
<img width="1043" height="90" alt="image" src="https://github.com/user-attachments/assets/fcdf0463-65d7-4fc8-aa76-6472379fb9d1" />

Base on our result that we scan above:
<img width="973" height="788" alt="image" src="https://github.com/user-attachments/assets/78e24978-a3be-4cd1-b23f-0848e2578cf7" />

Now we found the service `is running on the higher port` is `ssh`.

So the correct answer is:
````
ssh
````
<img width="1057" height="94" alt="image" src="https://github.com/user-attachments/assets/c0d3669e-36c2-4c3c-a76b-81dbb882c82c" />

---


## Question 3:
What's the CVE you're using against the application?
<img width="1054" height="95" alt="image" src="https://github.com/user-attachments/assets/47603a96-3ce4-4876-b2a6-3a69c2a5968f" />

In this i go to browser and type the target IP, cause it open port `80`:
````
http://10.48.186.93/
````
<img width="1342" height="860" alt="image" src="https://github.com/user-attachments/assets/507ec903-2a95-432e-87b8-4543737437fd" />

Now we after i input this to browser and then i see `Apache 2` service.

After back to our `Terminal` and in this i use `Gobuster`:
````
gobuster dir -u http://10.48.186.93/ -w /usr/share/wordlists/dirb/common.txt
````
<img width="1059" height="676" alt="image" src="https://github.com/user-attachments/assets/f830a08a-12e9-4946-b07a-b29a2afb59d9" />


### What we found & What It Means
| Path / File  | Status Code | Significance                                                                                                     |
| ------------ | ----------- | ---------------------------------------------------------------------------------------------------------------- |
| `robots.txt` | 200         | ⚠️ Check this first – often reveals hidden paths or disallowed directories that may contain interesting content. |
| `simple/`    | 301         | 🎯 Redirects to the vulnerable CMS Made Simple application. Likely the main target.                              |
| `.htaccess`  | 403         | Normal – Apache configuration file. Access is forbidden. Usually not directly exploitable.                       |
| `.htpasswd`  | 403         | Normal – Stores authentication credentials for Apache. Access blocked. Ignore for now.                           |

After we finished scan, and then check:
````
http://10.48.186.93/robots.txt
````
<img width="965" height="654" alt="image" src="https://github.com/user-attachments/assets/635d057f-ebdc-47e4-83df-11c161c07028" />

Key finding:
````
Disallow: /openemr-5_0_1_3
````
- After Check the discovered directory:
````
curl -L http://10.48.186.93/openemr-5_0_1_3/
````
<img width="772" height="235" alt="image" src="https://github.com/user-attachments/assets/ea00c1ba-3cc1-4386-b08b-0bbbe245a0a9" />


- Search for OpenEMR vulnerabilities:
````
searchsploit openemr
````
or
````
searchsploit openemr 5.0.1.3
````
<img width="766" height="392" alt="image" src="https://github.com/user-attachments/assets/4cff9ef0-c762-49ac-a5d1-2f481960610d" />
But in this we not found only `403`.



- And check our:
````
http://10.48.186.93/simple/
````
<img width="1345" height="857" alt="image" src="https://github.com/user-attachments/assets/9310ee3a-8a38-4378-a882-8600e91a1b3e" />

Now we see this and i want to see this source code, `Right-Click` -> `View Source Code`:
<img width="1917" height="857" alt="image" src="https://github.com/user-attachments/assets/33a85f45-5cfb-4a30-8e32-ea78b45732c3" />

Now i see `CMS Made Simple`, After go back to our `Terminal`, and then use `Google Hacking Database` go to: https://www.exploit-db.com/
<img width="1858" height="1016" alt="image" src="https://github.com/user-attachments/assets/22686a76-1d01-4cfe-972f-3905d83c0cd5" />

After click on it:
<img width="1768" height="972" alt="image" src="https://github.com/user-attachments/assets/b269730d-ae37-4e56-acc3-7bf424498eb0" />

Now we see the `CVE` is `CVE-2019-9053`.

So the correct answer is:
````
CVE-2019-9053
````
<img width="1047" height="87" alt="image" src="https://github.com/user-attachments/assets/039340ab-6336-46f8-b3f0-5c66bd971c7d" />

---


## Question 4:
To what kind of vulnerability is the application vulnerable?
<img width="1052" height="87" alt="image" src="https://github.com/user-attachments/assets/55249522-4493-48c5-97da-f815f59e0725" />

Base on what we found above now we get the `kind of vulnerability is the application vulnerable` is `SQL Injection`.

So the correct answer is:
````
sqli
````
<img width="1048" height="88" alt="image" src="https://github.com/user-attachments/assets/d8564880-714c-41af-b0bd-ea25ace9f13f" />

---




















