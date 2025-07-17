# AICTE_Cyber Security(CS)_Internship_B4_JAN-2025
This project was developed as part of the **Edunet Foundation internship**, a **6-week program** from **January 15, 2025** to **February 26, 2025**. 

# 🛡️ Image Steganography and Encryption Tool

### 👉 "For deployment details, scroll down 👇 or view the end of the README file (deployed in Streamlit.app)."

## 📌 Project Overview  
This project is a **Steganography and Encryption Tool** that allows users to **securely hide messages inside images** using **Least Significant Bit (LSB) encoding**. Additionally, messages are **encrypted with a password** to ensure data security.

---

## 🚀 Features  
✅ **Steganography + Encryption** – Dual-layer security to protect hidden messages.  
✅ **Password Protection** – Uses **Bcrypt hashing** for secure authentication.  
✅ **User-Friendly GUI** – Built with **Tkinter** for easy interaction.  
✅ **Cross-Platform Support** – Runs on **Windows, Linux, and macOS**.  
✅ **Supports PNG & JPG** – Hide and retrieve messages from images.  

---

## 🛠️ Technologies Used  

- **Programming Language:** Python  
- **Libraries:**  
  - `Pillow` – Image processing  
  - `Stegano` – Image steganography  
  - `Cryptography` – Message encryption  
  - `Bcrypt` – Secure password hashing  
- **Development Tools:** VS Code, IDLE  
- **Compatible OS:** Windows, Linux, macOS  

---

## 🔧 Installation & Setup  

### **1️⃣ Prerequisites**  
Ensure you have Python installed. Download from: [Python Official Website](https://www.python.org/)  

### **2️⃣ Install Required Libraries**  
Run the following command in the terminal:  
```bash
pip install pillow stegano cryptography bcrypt
```
Run the program:
```
image.py
```
### **3️⃣ Running the Application**
- Open the project folder in VS Code or IDLE.      
- Select an image, enter a message, and encrypt it!

---

### **🔑 Usage Guidelines**    
**For Encryption:**            
--> Choose a clear PNG/JPG image.             
--> Enter a strong password to protect the message.                     
--> Save the encoded image for future retrieval.                        
**For Decryption:**                         
--> Load the encoded image into the tool.                 
--> Enter the correct password to reveal the message.  

**⚠ Note:** If the wrong password is entered, decryption will fail!                             

---

📌 **Future Scope**                
🚀 **AES-256 Encryption** – Implementing even stronger encryption methods.                  
📱**Mobile App Development** – Expanding to Android/iOS.                  
☁ **Cloud Storage Integration** – Secure online storage and sharing.                      
🎵 **Audio/Video Steganography** – Hiding messages in media files.                          
                      
🏆 **Conclusion**       
This project addresses the growing need for **secure digital communication** by integrating encryption with steganography. It provides a **user-friendly** way to protect sensitive information and can be expanded with advanced **security features** in the future.   

---
# ----->🌍 Deployment details<-----
**Streamlit does not support Tkinter** because Streamlit is a web-based framework, while Tkinter is a GUI library for desktop applications.
However, there are some **similar functionality** in Streamlit, we can use **Streamlit's built-in widgets** (st.button, st.text_input, st.selectbox, etc.) to create interactive elements instead of using Tkinter.

# **Changes Made for Streamlit Deployment**
The **core algorithm remains the same**, but modifications were made to adapt the application for Streamlit, since Tkinter is not supported in Streamlit.

**Key Changes:**            
✅ Removed Tkinter UI elements and replaced them with Streamlit widgets.             
✅ Used st.file_uploader instead of Tkinter's file dialogs.               
✅ Modified event-based logic to align with Streamlit’s reactive model.            

# Required Files:                      
1. **app.py** → The main Streamlit script.                              
2. **requirements.txt** → Contains all required Python dependencies.
3. **packages.txt** → need to tell Streamlit to install this system dependency by using a special file called packages.txt.
          

## 👉 "For more detailed information, check out the 'Deployed' directory/folder."

### **🎓 Credits**               
Developed by **Nikhil K**   

## **_🔒 Stay Secure, Stay Private! 🔐_**


