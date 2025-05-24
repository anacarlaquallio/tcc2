# RSA Implementations

This repository contains RSA implementations in C, C++, Java, JavaScript, Python, and Rust. For each language, two libraries were selected: OpenSSL and Libgcrypt (C), Botan and CryptoPP (C++), Bouncy Castle and Java Crypto (Java), Forge and Crypto (JavaScript), Cryptography and PyCryptodome (Python), and finally Rust OpenSSL and Rust Crypto (Rust).

This repository is my final project for a Bachelor's Degree in Computer Science and involves evaluating different implementations of the RSA encryption system.

 ## Summary
- [Abstract](#abstract)  
- [Installation](#installation)
- [Usage](#usage)  
- [Results](#results) 

## Abstract
 With the increasing flow of information between different devices, encryption systems have become essential to ensure data authenticity, confidentiality, and integrity. A common approach is asymmetric encryption, which uses two keys: one for encrypting messages and another for decrypting them. In this context, the RSA algorithm emerges as one of the most widely adopted encryption systems. This study aims to evaluate RSA implementations, investigating the impact of adopting different approaches, including selecting libraries within the same programming language and using various programming languages. Experiments were conducted in C, C++, Java, JavaScript, Python, and Rust, using two libraries per language: OpenSSL and Libgcrypt (C), Botan and Crypto++ (C++), Bouncy Castle and Java Crypto (Java), Forge and Crypto (JavaScript), Cryptography and PyCryptodome (Python), and Rust OpenSSL and Rust Crypto (Rust). The analysis of average execution times demonstrated that Rust, C, and Python achieved the best performance in encryption and decryption processes, mainly due to their implementations' use of OpenSSL as the foundation. Regarding key generation, C++ and Python obtained the shortest average times for 2048, 3072 and 4096-bit keys. Additionally, an analysis of confidential data storage structures revealed similar patterns used to store private keys across the studied languages. Finally, a memory dump analysis exposed fragments of private keys in various libraries. In the case of JavaScript, it was possible to recover the private key entirely in both tested implementations, highlighting a vulnerability that could compromise system security if an attacker gains access to the program's core dump. The results provide a basis for selecting RSA implementations, considering performance and security.

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

The experiments were conducted on a machine with an AMD Ryzen 5 processor (64-bit), 12 GB of RAM, a 240 GB NVMe SSD, and the Linux Mint 22.1 Xia - 64-bit operating system. The executions took place in the Xfce graphical interface, taking into account system processes and the terminal running during the tests.

The spreadsheet with the complete results is available at the following link:
https://docs.google.com/spreadsheets/d/1v0xcE82KvdqZiBZfxzAQDSQn3kZct6Qieq9O0e7JRy0/edit?usp=sharing