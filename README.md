# RSA Implementations

This repository contains RSA implementations in C, C++, Java, JavaScript, Python, and Rust. For each language, two libraries were selected: OpenSSL and Libgcrypt (C), Botan and CryptoPP (C++), Bouncy Castle and Java Crypto (Java), Forge and Crypto (JavaScript), Cryptography and PyCryptodome (Python), and finally Rust OpenSSL and Rust Crypto (Rust).

This repository is my final project for a Bachelor's Degree in Computer Science and involves evaluating different implementations of the RSA encryption system.

 ## Summary
- [Abstract](#abstract)  
- [Installation](#installation)
- [Usage](#usage)  
- [Results](#results) 

## Abstract
 With the increasing flow of information between different devices, encryption systems have become essential to ensure data authenticity, confidentiality, and integrity. A common approach is asymmetric encryption, which uses two keys: one for encrypting messages and another for decrypting them. In this context, the RSA algorithm emerges as one of the most widely adopted encryption systems. This study aims to evaluate RSA implementations, investigating the impact of adopting different approaches, including selecting libraries within the same programming language and using various programming languages. Experiments were conducted in C, C++, Java, JavaScript, Python, and Rust, using two libraries per language: OpenSSL and Libgcrypt (C), Botan and Crypto++ (C++), Bouncy Castle and Java Crypto (Java), Forge and Crypto (JavaScript), Cryptography and PyCryptodome (Python), and Rust OpenSSL and Rust Crypto (Rust). The analysis of average execution times demonstrated that Rust, C, and Python achieved the best performance in encryption and decryption processes, mainly due to their implementations' use of OpenSSL as the foundation. Regarding key generation, C++ and Python obtained the shortest average times for 2048 and 4096-bit keys. Additionally, an analysis of confidential data storage structures revealed similar patterns used to store private keys across the studied languages. Finally, a memory dump analysis exposed fragments of private keys in various libraries. In the case of JavaScript, it was possible to recover the private key entirely in both tested implementations, highlighting a vulnerability that could compromise system security if an attacker gains access to the program's core dump. The results provide a basis for selecting RSA implementations, considering performance and security.

## Installation  

Each library requires different packages and dependencies. Follow the instructions below for each one:  

### **C Libraries**  
- **OpenSSL**  
  ```bash
  sudo apt install libssl-dev
  ```  

- **Libgcrypt**  
  ```bash
  sudo apt install libgcrypt20-dev
  ```  

### **C++ Libraries**  
- **Botan**  
  ```bash
  git clone https://github.com/randombit/botan.git
  cd botan
  ./configure.py
  make
  sudo make install
  ```  

- **Crypto++**  
  ```bash
  sudo apt install libcrypto++-dev
  ```  

### **Java Libraries**  
- **Bouncy Castle and Java Crypto**  
  The **`pom.xml`** file already includes the required dependencies. You only need to install Maven:  
  ```bash
  sudo apt install maven
  ```  

### **JavaScript Library**  
- **Forge**  
  ```bash
  npm install node-forge
  ```  

### **Python Libraries**  
- **Cryptography and PyCryptodome**  
  ```bash
  pip install cryptography pycryptodome matplotlib tabulate pytest pytest-benchmark
  ```  

### **Rust Libraries**  
- **Rust OpenSSL and Rust Crypto**  
  Dependencies are already included in **`Cargo.toml`**. Ensure you have Rust installed.

## Usage

### **Keys**  
You can generate the public and private keys using the following commands:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key.pem
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### **Message**  
Load your message into a `.txt` file, ensuring that you respect the maximum padding for the key and the library being used.

### Core Dump with gcore
To generate a core dump using gcore, first, you need to identify the process ID (PID) of the target process:
```bash
ps aux | grep <process_name>
sudo gcore -o target <pid>
```

### **C Libraries**  
To compile and run the C implementation:

```bash
make
./main
```

### **C++ Libraries**  
To compile and run the C++ implementation:

```bash
make
./main
```

### **Java Libraries**  
For the Java implementation, build and run the project using Maven:

```bash
mvn clean verify
java -jar target/benchmarks.jar
```

### **JavaScript Libraries**  
Run the JavaScript implementation with Node.js:

```bash
node rsa_test.js
```

### **Python Libraries**  
Run the Python tests with pytest:

```bash
pytest
```

### **Rust Libraries**  
Run the Rust benchmarks:

```bash
cargo benchmark
```

## Results

The experiments were conducted on a machine with an AMD Ryzen 5 processor (64-bit), 12 GB of RAM, and Debian 12 (Bookworm - 64-bit) operating system. The executions took place in the GNOME graphical interface, considering system processes and the terminal running during the tests, which were conducted over 6 days.
Certain standards were adopted to ensure consistency. For all executions, a message file in the .txt format with 90 bytes was used, corresponding to the maximum padding allowed by a 2048-bit RSA key in the JavaScript Forge library. The 2048 and 4096-bit keys were pre-generated with OpenSSL and used in the encryption and decryption processes across all languages. This way, the implementations load the message and public and private keys directly into the code, ensuring stability in the obtained results. A summary of the results is shown below:

### Encryption - 2048 bits

| Key   | Library           | Mean time (ms)|
|-------|-------------------|---------------|
| 2048  | Rust OpenSSL      | 0,02554477648 |
|       | OpenSSL           | 0,03096105333 |
|       | Cryptography      | 0,03488271889 |
|       | Botan             | 0,04467732804 |
|       | Java Crypto       | 0,04471018112 |
|       | Bouncy Castle     | 0,04841525077 |
|       | Libgcrypt         | 0,05155833333 |
|       | Crypto++          | 0,05209929252 |
|       | Crypto (JS)       | 0,2444477433  |
|       | Rust Crypto       | 0,2528954308  |
|       | Pycryptodome      | 0,4669065086  |
|       | Forge             | 0,8983660542  |
---

### Encryption - 4096 bits

| Key   | Library           | Mean time (ms)|
|-------|-------------------|---------------|
| 4096  | Rust OpenSSL      | 0,08893466647 |
|       | OpenSSL           | 0,09460076667 |
|       | Cryptography      | 0,1057023767  |
|       | Crypto++          | 0,1271352516  |
|       | Libcrypt          | 0,1331744133  |
|       | Botan             | 0,1400091212  |
|       | Bouncy Castle     | 0,1537197002  |
|       | Java Crypto       | 0,1578224569  |
|       | Crypto (JS)       | 0,3220664306  |
|       | Rust Crypto       | 0,9493025126  |
|       | Pycryptodome      | 0,9540326783  |
|       | Forge             | 3,380141842   |

### Decryption - 2048 bits

| Key   | Library           | Mean time (ms)|
|-------|-------------------|---------------|
| 2048  | Rust OpenSSL      | 0,7829312865  |
|       | OpenSSL           | 0,7973404267  |
|       | Cryptography      | 0,8013283419  |
|       | Bouncy Castle     | 1,15858271    |
|       | Crypto++          | 1,169133677   |
|       | Java Crypto       | 1,174354951   |
|       | Pycryptodome      | 1,304710285   |
|       | Botan             | 1,671762809   |
|       | Crypto (JS)       | 1,900036322   |
|       | Rust Crypto       | 1,92716366    |
|       | Libgcrypt         | 9,306325673   |
|       | Forge             | 24,50991604   |

### Decryption - 4096 bits

| Key   | Library           | Mean time (ms)|
|-------|-------------------|---------------|
| 4096  | Cryptography      | 5,543411269   |
|       | OpenSSL           | 5,546986167   |
|       | Rust OpenSSL      | 5,557571411   |
|       | Pycryptodome      | 6,69741999    |
|       | Crypto++          | 7,301236939   |
|       | Crypto (JS)       | 7,584548987   |
|       | Bouncy Castle     | 8,137691063   |
|       | Java Crypto       | 8,209565693   |
|       | Botan             | 9,761696616   |
|       | Rust Crypto       | 14,33964687   |
|       | Libgcrypt         | 54,2784834    |
|       | Forge             | 216,905779    |
