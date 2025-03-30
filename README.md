# Comparative Analysis of Argon2, Bcrypt, Scrypt, and MD5: Security, Resistance to Attacks, and Resource Utilization and Consumption
> One of the most fundamental aspects of cyber security is user authentication, which is the act of ensuring that any entity wishing to access a system and 
the information within it have the permission to do so. Out of all authentication methods, those that are password based are the most common, and password
hashing algorithms are used to help mask a user's password when stored on the backend database. Hashing is the algorithmic process of taking a variable length
input string, known as the key, and producing a fixed length unintelligible string of characters designed to protect the password from unauthorized access. As 
cyberattacks continue to evolve, new techniques, such as dictionary and rainbow table attacks, have been devloped to exploit vulnerabilities in weak password hashing schemes. 

 > The objective of this project is to compare four different password hashing algorithms: Argon2, Bcrypt, Scrypt, and MD5 under different time and memory constraints. These algorithms will be compared based on their 
resistance to various cryptographic attacks, including dictionary, brute-force, and time-memory trade-off attacks, as well as their resource utilization and consumption. A python script will be developed to implement
each hashing algorithm and produce a variety of passwords of varying complexity along with their corresponding hash. These passwords will then be stored in a text file and passed through to HashCat, which will be used 
to simulate the specified attacks and document how long it takes to crack the passwords when the hash is generated using a specific algorithm, as well as specify the amount of memory allocated. Graphs will be used to illustrate the time needed to crack a password 
of a specified complexity when using a specified hashing algorithm, as well as CPU and RAM usage for that algorithm. Using the results, it will be determined which password hashing algorithm offers the best performance
and security against different cyber attacks. An academic research paper and presentation will be produced upon the completion of this project. All files and the source code for the hashing algorithms will be posted to this repository when available. 

