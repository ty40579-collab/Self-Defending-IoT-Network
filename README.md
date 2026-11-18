# Self-Defending IoT Network



A Flask-based IoT network security application that uses a pre-trained Random Forest machine-learning model to classify uploaded network traffic records and display security alerts.



## Features



- Upload network traffic CSV files for analysis.

- Classify traffic using a pre-trained Random Forest model.

- Display total, safe, and attack record counts.

- Store security alerts in an SQLite database.

- View dashboard, monitoring, traffic, threats, devices, response, performance, and alert pages.

- Display simulated device-isolation responses.



## Technology Stack



- Python 3.12

- Flask

- Scikit-learn

- Random Forest

- NumPy

- Pandas

- Joblib

- SQLite

- HTML and CSS



## Main Project Files



- `app.py` - Flask application.

- `models/random_forest_model.pkl` - Pre-trained machine-learning model.

- `src/prediction.py` - Traffic prediction.

- `src/database.py` - SQLite database operations.

- `templates/` - HTML pages.

- `static/css/style.css` - Application styling.

- `requirements.txt` - Python dependencies.



## Installation and Setup



### 1. Clone the repository



Run:



`git clone https://github.com/ty40579-collab/Self-Defending-IoT-Network.git`



Then:



`cd Self-Defending-IoT-Network`



### 2. Create a virtual environment



`python -m venv .venv`



Activate on Windows:



`.venv\Scripts\Activate.ps1`



Activate on Linux or macOS:



`source .venv/bin/activate`



### 3. Install dependencies



`python -m pip install -r requirements.txt`



### 4. Run the application



`python app.py`



### 5. Open the application



Visit http://127.0.0.1:5000



The application creates its SQLite database (`iot_security.db`) automatically when it starts.



## Machine Learning Model



The repository includes a pre-trained Random Forest model.



- Model location: `models/random_forest_model.pkl`

- Expected input features: 39

- Classification: benign traffic and attack traffic.



Uploaded CSV files must contain compatible feature columns expected by the trained model.



The original training datasets are not included. The pre-trained model allows inference without retraining.



## Current Scope and Limitations



- Traffic analysis uses uploaded CSV files; continuous live packet capture is not implemented.

- The model performs binary traffic classification; it is not a general-purpose detector for every IoT attack.

- Device isolation is simulated and does not enforce isolation on a physical network.

- Automatic device recovery and reconnection are not implemented.

- Some dashboard and performance values are demonstration data.



## Database



SQLite stores security alerts. The database file is generated locally and is not included in the repository.



## Important Note



This project is an academic and software demonstration. It should not be treated as a production-ready network intrusion prevention system.
