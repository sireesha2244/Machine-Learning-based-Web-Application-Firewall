📌 Project Overview

This project presents a Machine Learning-Based Web Application Firewall designed to detect and classify web-based attacks such as SQL Injection (SQLi), Cross-Site Scripting (XSS), and Local File Inclusion (LFI).

Unlike traditional rule-based systems, this solution uses machine learning models to analyze input features and identify attack patterns. The system also integrates Explainable AI (SHAP) to provide transparency by showing how each feature influences the prediction.

🚀 Key Features
🔍 Detection of web attacks (SQLi, XSS, LFI)
🤖 Machine Learning-based classification
📊 SHAP-based explainability for predictions
🌐 User-friendly Flask web interface
🔐 User authentication (Login/Register)
⚡ Real-time prediction system
🧠 Technologies Used
Backend
Python
Flask
Machine Learning
XGBoost
LightGBM
Random Forest
Scikit-learn
Explainable AI
SHAP (SHapley Additive Explanations)
Frontend
HTML
CSS
Bootstrap
JavaScript
Database
MySQL (via XAMPP)
📂 Project Structure
Machine-Learning-WAF/
│
├── BACKEND/              # Model training and dataset
│   └── code.ipynb
│
├── FRONT END/           # Flask web application
│   ├── app.py
│   ├── templates/
│   ├── static/
│   └── models/
│
├── .gitignore
└── README.md
⚙️ How It Works
User inputs feature values through the web interface
Input is preprocessed and formatted
Machine learning model predicts attack type
SHAP generates feature-level explanation
Result is displayed with confidence score
▶️ How to Run the Project
1. Clone the Repository
2. Install Dependencies
pip install -r requirements.txt
(or manually install: Flask, xgboost, lightgbm, shap, pandas, numpy, sklearn)

3. Setup Database
Start XAMPP
Create MySQL database
Update database credentials in app.py
4. Run the Application
python app.py
5. Open in Browser
http://127.0.0.1:5000
📊 Output
Predicted attack type (SQLi / XSS / LFI / Normal)
Confidence score
SHAP-based feature contribution analysis
⚠️ Limitations
Does not perform automatic request blocking (detection-only system)
Uses pre-trained models (not real-time training)
Dataset may not fully represent real-world traffic
🔮 Future Enhancements
Real-time request blocking (full WAF implementation)
Integration with live web servers
Improved dataset and model accuracy
Deployment on cloud platforms
Advanced visualization dashboards

👨‍💻 Author
Sireesha
