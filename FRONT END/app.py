import matplotlib
matplotlib.use('Agg')  # MUST BE FIRST - fixes Tkinter/thread errors in Flask

from flask import Flask, render_template, redirect, url_for, request, session
import mysql.connector
import joblib
import numpy as np
import shap
import matplotlib.pyplot as plt
import io
import base64
import pymysql
import joblib
import numpy as np
import pandas as pd
import shap
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)
app.secret_key = 'IOT'

mydb = pymysql.connect(
    host="localhost",
    user="root",
    password="",
    port=3306,
    database='IOT'
)

mycursor = mydb.cursor()

def executionquery(query, values):
    mycursor.execute(query, values)
    mydb.commit()
    return

def retrivequery1(query, values):
    mycursor.execute(query, values)
    data = mycursor.fetchall()
    return data

def retrivequery2(query):
    mycursor.execute(query)
    data = mycursor.fetchall()
    return data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        c_password = request.form['c_password']

        if password == c_password:
            query = "SELECT email FROM users"
            email_data = retrivequery2(query)
            email_data_list = [i[0] for i in email_data]

            if email not in email_data_list:
                query = "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)"
                values = (name, email, password)
                executionquery(query, values)
                return render_template('login.html', message="Successfully Registered!")
            return render_template('register.html', message="This email ID already exists!")
        return render_template('register.html', message="Confirm password does not match!")
    return render_template('register.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        query = "SELECT email FROM users"
        email_data = retrivequery2(query)
        email_data_list = [i[0] for i in email_data]

        if email in email_data_list:
            query = "SELECT * FROM users WHERE email = %s"
            values = (email,)
            user_data = retrivequery1(query, values)
            if password == user_data[0][3]:
                session["user_email"] = email
                session["user_id"] = user_data[0][0]
                session["user_name"] = user_data[0][1]
                return redirect("/home")
            return render_template('login.html', message="Invalid Password!!")
        return render_template('login.html', message="This email ID does not exist!")
    return render_template('login.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route("/model")
def model():
    return render_template("model.html")



# Load artifacts
median_values = joblib.load('models/median_values.pkl')      # dict with all original columns
top_features = joblib.load('models/top_features.pkl')        # list of 15 feature names
xgb_model = joblib.load('models/xgb_model.pkl')              # XGBoost model (3 classes)

# Attack mapping (as per your spec)
attack_names = {
    0: 'Cross-Site Scripting (XSS)',
    1: 'Local File Inclusion (LFI)',
    2: 'SQL Injection'
}

def preprocess_new_input(form_dict, median_values, top_features):
    """Convert form data to DataFrame, fill missing, return top features only."""
    df_new = pd.DataFrame([form_dict])
    # Ensure all columns from median_values exist
    all_cols = list(median_values.keys())
    for col in all_cols:
        if col not in df_new.columns:
            df_new[col] = np.nan
    # Fill NaN with median values
    for col in median_values:
        df_new[col] = df_new[col].fillna(median_values[col])
    # Keep only top features
    X_new = df_new[top_features]
    return X_new

@app.route('/prediction', methods=["GET", "POST"])
def prediction():
    result = None
    shap_html = None

    if request.method == "POST":
        try:
            # 1. Collect form inputs (must match top_features)
            form_data = {
                'Src IP dec': float(request.form['Src IP dec']),
                'Bwd Packet Length Std': float(request.form['Bwd Packet Length Std']),
                'Packet Length Max': float(request.form['Packet Length Max']),
                'Flow Duration': float(request.form['Flow Duration']),
                'Average Packet Size': float(request.form['Average Packet Size']),
                'Bwd Packet Length Max': float(request.form['Bwd Packet Length Max']),
                'Bwd Packet Length Mean': float(request.form['Bwd Packet Length Mean']),
                'Packet Length Mean': float(request.form['Packet Length Mean']),
                'Packet Length Std': float(request.form['Packet Length Std']),
                'Packet Length Variance': float(request.form['Packet Length Variance']),
                'Bwd Segment Size Avg': float(request.form['Bwd Segment Size Avg']),
                'Fwd Packet Length Max': float(request.form['Fwd Packet Length Max']),
                'Fwd Packet Length Mean': float(request.form['Fwd Packet Length Mean']),
                'Flow IAT Max': float(request.form['Flow IAT Max']),
                'Subflow Bwd Bytes': float(request.form['Subflow Bwd Bytes'])
            }

            # 2. Preprocess
            X_new = preprocess_new_input(form_data, median_values, top_features)

            # 3. Predict
            pred_class = int(xgb_model.predict(X_new)[0])
            pred_proba = xgb_model.predict_proba(X_new)[0]
            confidence = pred_proba[pred_class] * 100
            attack_name = attack_names.get(pred_class, "Unknown")
            result = f"Predicted Attack: {attack_name} (Confidence: {confidence:.2f}%)"

            # 4. SHAP Explanation
            explainer = shap.TreeExplainer(xgb_model)
            shap_values = explainer.shap_values(X_new)

            # Robust extraction for multi‑class (as in your diagnostic code)
            if isinstance(shap_values, list) and len(shap_values) == xgb_model.n_classes_:
                # Ideal case: list of arrays per class
                shap_vals_for_class = shap_values[pred_class][0]
                base_val = explainer.expected_value[pred_class]
            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
                # 3D array: (samples, features, classes)
                shap_vals_for_class = shap_values[0, :, pred_class]
                base_val = explainer.expected_value[pred_class] if isinstance(explainer.expected_value, list) else explainer.expected_value
            else:
                # Fallback: try to reconstruct explainer with probability output
                explainer = shap.TreeExplainer(xgb_model, model_output='probability')
                shap_values = explainer.shap_values(X_new)
                if isinstance(shap_values, list) and len(shap_values) == xgb_model.n_classes_:
                    shap_vals_for_class = shap_values[pred_class][0]
                    base_val = explainer.expected_value[pred_class]
                else:
                    raise RuntimeError("Could not extract per‑class SHAP values.")

            # Create Explanation object for waterfall plot
            explanation = shap.Explanation(
                values=shap_vals_for_class,
                base_values=base_val,
                data=X_new.iloc[0].values,
                feature_names=top_features
            )

            # Generate waterfall plot as base64 image
            plt.figure(figsize=(12, 6))
            shap.waterfall_plot(explanation, show=False)
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight', dpi=120)
            buf.seek(0)
            waterfall_base64 = base64.b64encode(buf.read()).decode('utf-8')
            plt.close()

            # Top 10 features by absolute SHAP value
            abs_shap = np.abs(shap_vals_for_class)
            top_indices = np.argsort(abs_shap)[-10:][::-1]
            top_features_list = []
            for idx in top_indices:
                feat = top_features[idx]
                val = shap_vals_for_class[idx]
                direction = "↑ increases" if val > 0 else "↓ decreases"
                top_features_list.append(f"<li><b>{feat}</b>: {direction} by {val:.4f}</li>")

            # Combine everything into shap_html
            shap_html = f"""
            <div style="background: white; border-radius: 8px; padding: 20px; overflow-x: auto;">
                <h4 style="color: #004d40; text-align: center;">SHAP Waterfall Plot (for predicted class)</h4>
                <img src="data:image/png;base64,{waterfall_base64}" style="max-width:100%; height:auto; border:1px solid #ccc; border-radius:8px;">
                <hr>
                <h5 style="color: #004d40;">Top 10 Contributing Features</h5>
                <ul style="list-style-type:none; padding-left:0;">
                    {''.join(top_features_list)}
                </ul>
                <p style="text-align:center; color:#7f8c8d;">
                    <small>Red = pushes prediction higher • Blue = pushes prediction lower</small>
                </p>
            </div>
            """

        except Exception as e:
            result = f"Error during prediction: {str(e)}"
            shap_html = f'<p style="color:#c0392b; text-align:center;">SHAP generation failed: {str(e)}</p>'

    return render_template('prediction.html', result=result, shap_html=shap_html)

if __name__ == '__main__':
    app.run(debug=True)