import joblib
import pandas as pd
import numpy as np


MODEL_PATH = "models/random_forest_model.pkl"


def predict_file(csv_path):

    model = joblib.load(MODEL_PATH)

    df = pd.read_csv(csv_path)

    # Remove infinities
    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    # Fill NaN values
    df.fillna(0, inplace=True)
    
    numeric_cols = df.select_dtypes(
        include=["number"]
    ).columns

    df[numeric_cols] = df[numeric_cols].clip(
        lower=-1e10,
        upper=1e10
    )

    predictions = model.predict(df)

    attack_count = int(predictions.sum())
    
    total = len(predictions)

    return {
        "total_records": total,
        "attack_records": attack_count,
        "safe_records": total - attack_count
    }