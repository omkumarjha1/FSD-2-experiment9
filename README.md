# PRACTICAL RECORD: EXPERIMENT-8
**Course:** AIT-CSE (Cloud & DevOps)  
**Institution:** Chandigarh University  

---

## 👤 Student Information
* **Name:** Himangi Bhatt
* **UID:** 23BCC70020
* **Date of Submission:** 27th February, 2026

---

## 🎯 Aim
To develop and deploy a **RESTful API** using the **Python Flask** backend framework to perform CRUD (Create, Read, Update, and Delete) operations on student data stored in-memory.

## 🛠️ Software Requirements
* **Language:** Python 3.x
* **Framework:** Flask
* **API Testing Tool:** Postman
* **Deployment Platform:** Render
* **IDE:** Visual Studio Code

## 📝 Problem Statement
Develop a backend server that manages student records. The system must:
1. Support **GET** requests to retrieve student data.
2. Support **POST** requests to add new student records.
3. Support **PUT** requests to modify existing data.
4. Support **DELETE** requests to remove data.
5. Store data in a volatile **in-memory array**.

## 📊 API Endpoint Table
| Method | Endpoint | Description | Status Code |
| :--- | :--- | :--- | :--- |
| **GET** | `/students` | Fetch all student records | 200 OK |
| **POST** | `/students` | Add a new student record | 201 Created |
| **PUT** | `/students/<id>` | Update student by ID | 200 OK |
| **DELETE** | `/students/<id>` | Delete student by ID | 204 No Content |

## ✅ Conclusion
The RESTful API was successfully developed and tested using Postman. The application demonstrates core backend principles and is ready for deployment on the Render platform.